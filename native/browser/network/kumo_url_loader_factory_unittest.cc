// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_url_loader_factory.h"
#include "chrome/browser/kumo/network/kumo_network_admission.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/test/task_environment.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/cpp/url_loader_factory_builder.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/parsed_headers.mojom.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace kumo {
namespace {
class TestLoad final : public network::mojom::URLLoader {
 public:
  TestLoad(mojo::PendingReceiver<network::mojom::URLLoader> receiver,
           int32_t id, uint32_t flags, const network::ResourceRequest& resource,
           mojo::PendingRemote<network::mojom::URLLoaderClient> remote,
           const net::MutableNetworkTrafficAnnotationTag& tag)
      : request_id(id), options(flags), request(resource), annotation(tag),
        client(std::move(remote)), receiver_(this, std::move(receiver)) {
    receiver_.set_disconnect_handler(base::BindOnce(
        [](bool* closed) { *closed = true; }, &closed));
  }
  void FollowRedirect(network::HttpRequestHeadersUpdateParams update,
                      const std::optional<GURL>& replacement) override {
    ++follows; headers = std::move(update); new_url = replacement;
  }
  void SetPriority(net::RequestPriority priority, int32_t intra) override {
    priorities.emplace_back(priority, intra);
  }
  void Redirect(const GURL& url) {
    net::RedirectInfo info; info.new_url = url; info.status_code = 307;
    client->OnReceiveRedirect(info, network::mojom::URLResponseHead::New());
  }
  int32_t request_id;
  uint32_t options;
  network::ResourceRequest request;
  net::MutableNetworkTrafficAnnotationTag annotation;
  mojo::Remote<network::mojom::URLLoaderClient> client;
  int follows = 0;
  bool closed = false;
  network::HttpRequestHeadersUpdateParams headers;
  std::optional<GURL> new_url;
  std::vector<std::pair<net::RequestPriority, int32_t>> priorities;
 private:
  mojo::Receiver<network::mojom::URLLoader> receiver_;
};

class TestFactory final : public network::mojom::URLLoaderFactory {
 public:
  void BindReceiver(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver) {
    receivers_.Add(this, std::move(receiver));
  }
  mojo::PendingRemote<network::mojom::URLLoaderFactory> Bind() {
    mojo::PendingRemote<network::mojom::URLLoaderFactory> remote;
    receivers_.Add(this, remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }
  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver) override {
    receivers_.Add(this, std::move(receiver));
  }
  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id, uint32_t options,
      const network::ResourceRequest& request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation) override {
    loads.push_back(std::make_unique<TestLoad>(std::move(receiver), request_id,
        options, request, std::move(client), annotation));
  }
  std::vector<std::unique_ptr<TestLoad>> loads;
 private:
  mojo::ReceiverSet<network::mojom::URLLoaderFactory> receivers_;
};

// Models an upstream extension or DevTools rewriter. The gate must inspect the
// rewritten destination rather than trusting the original admitted URL.
class RewritingFactory final : public network::mojom::URLLoaderFactory {
 public:
  void BindReceiver(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver) {
    receivers_.Add(this, std::move(receiver));
  }
  mojo::PendingRemote<network::mojom::URLLoaderFactory> Bind() {
    mojo::PendingRemote<network::mojom::URLLoaderFactory> remote;
    BindReceiver(remote.InitWithNewPipeAndPassReceiver()); return remote;
  }
  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver) override {
    BindReceiver(std::move(receiver));
  }
  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t id, uint32_t options, const network::ResourceRequest& request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation) override {
    ++calls; network::ResourceRequest rewritten(request);
    rewritten.url = GURL("https://blocked.invalid/rewritten");
    target->CreateLoaderAndStart(std::move(receiver), id, options, rewritten,
                                 std::move(client), annotation);
  }
  int calls = 0;
  mojo::Remote<network::mojom::URLLoaderFactory> target;
 private:
  mojo::ReceiverSet<network::mojom::URLLoaderFactory> receivers_;
};

class TestClient final : public network::mojom::URLLoaderClient {
 public:
  mojo::PendingRemote<network::mojom::URLLoaderClient> Bind() {
    return receiver_.BindNewPipeAndPassRemote();
  }
  void Disconnect() { receiver_.reset(); }
  void OnReceiveEarlyHints(network::mojom::EarlyHintsPtr value) override {
    hints = std::move(value);
  }
  void OnReceiveResponse(network::mojom::URLResponseHeadPtr value,
      mojo::ScopedDataPipeConsumerHandle stream,
      std::optional<mojo_base::BigBuffer> cached) override {
    head = std::move(value); body = std::move(stream); metadata = std::move(cached);
  }
  void OnReceiveRedirect(const net::RedirectInfo& info,
                         network::mojom::URLResponseHeadPtr value) override {
    redirects.push_back(info); redirect_head = std::move(value);
  }
  void OnUploadProgress(int64_t current, int64_t total,
                        OnUploadProgressCallback ack) override {
    upload = std::make_pair(current, total);
    if (defer_upload_ack) deferred_ack = std::move(ack);
    else std::move(ack).Run();
  }
  void OnTransferSizeUpdated(int32_t difference) override { transfer += difference; }
  void OnComplete(const network::URLLoaderCompletionStatus& value) override {
    completions.push_back(value);
  }
  network::mojom::EarlyHintsPtr hints;
  network::mojom::URLResponseHeadPtr head, redirect_head;
  mojo::ScopedDataPipeConsumerHandle body;
  std::optional<mojo_base::BigBuffer> metadata;
  std::vector<net::RedirectInfo> redirects;
  std::vector<network::URLLoaderCompletionStatus> completions;
  std::optional<std::pair<int64_t, int64_t>> upload;
  int32_t transfer = 0;
  bool defer_upload_ack = false;
  OnUploadProgressCallback deferred_ack;
 private:
  mojo::Receiver<network::mojom::URLLoaderClient> receiver_{this};
};

class KumoDomainFactoryTest : public testing::Test {
 protected:
  static void SetUpTestSuite() { mojo::core::Init(); }
  DomainAdmission Checker() {
    return base::BindRepeating(&KumoDomainFactoryTest::Admit,
                               base::Unretained(this));
  }
  void SetUp() override {
    network::URLLoaderFactoryBuilder builder;
    AppendDomainURLLoaderFactory(builder, Checker());
    factory_.Bind(std::move(builder).Finish<
        mojo::PendingRemote<network::mojom::URLLoaderFactory>>(terminal_.Bind()));
  }
  void TearDown() override {
    client_.Disconnect(); loader_.reset(); factory_.reset();
    tasks_.RunUntilIdle(); tasks_.FastForwardBy(base::Seconds(16));
  }
  void Admit(const GURL& url, base::OnceCallback<void(bool)> callback) {
    checked_.push_back(url);
    if (timed_) {
      AwaitNetworkAdmission(base::BindRepeating(
          [](std::optional<bool>* value) { return *value; }, &timed_answer_),
          std::move(callback), base::Seconds(15));
      return;
    }
    if (pending_) { pending_callbacks_.push_back(std::move(callback)); return; }
    std::move(callback).Run(available_ && url.host() != "blocked.invalid");
  }
  void Begin(const GURL& url = GURL("https://allowed.invalid/start")) {
    network::ResourceRequest request; request.url = url;
    BeginRequest(request);
  }
  void BeginRequest(const network::ResourceRequest& request) {
    factory_->CreateLoaderAndStart(loader_.BindNewPipeAndPassReceiver(), 417,
        network::mojom::kURLLoadOptionSendSSLInfoWithResponse, request,
        client_.Bind(), net::MutableNetworkTrafficAnnotationTag(
                            TRAFFIC_ANNOTATION_FOR_TESTS));
    tasks_.RunUntilIdle();
  }
  void Decide(bool allowed) {
    auto callbacks = std::move(pending_callbacks_);
    for (auto& callback : callbacks) std::move(callback).Run(allowed);
    tasks_.RunUntilIdle();
  }
  base::test::TaskEnvironment tasks_{
      base::test::TaskEnvironment::MainThreadType::IO,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  TestFactory terminal_;
  mojo::Remote<network::mojom::URLLoaderFactory> factory_;
  mojo::Remote<network::mojom::URLLoader> loader_;
  TestClient client_;
  bool pending_ = false, available_ = true;
  bool timed_ = false;
  std::optional<bool> timed_answer_;
  std::vector<GURL> checked_;
  std::vector<base::OnceCallback<void(bool)>> pending_callbacks_;
};

TEST_F(KumoDomainFactoryTest, ListedInitialURLNeverReachesTerminal) {
  Begin(GURL("https://blocked.invalid/secret"));
  EXPECT_TRUE(terminal_.loads.empty());
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
  tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_EQ(client_.completions.size(), 1u);
}

TEST_F(KumoDomainFactoryTest, LatePriorityAfterInitialBlockIsHarmless) {
  Begin(GURL("https://blocked.invalid/start"));
  loader_->SetPriority(net::HIGHEST, 9); tasks_.RunUntilIdle();
  EXPECT_TRUE(terminal_.loads.empty()); ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, LatePriorityAfterTerminalErrorIsHarmless) {
  Begin(); client_.defer_upload_ack = true; bool acknowledged = false;
  terminal_.loads[0]->client->OnUploadProgress(1, 2, base::BindOnce(
      [](bool* value) { *value = true; }, &acknowledged));
  tasks_.RunUntilIdle(); ASSERT_TRUE(client_.deferred_ack);
  EXPECT_FALSE(acknowledged);
  terminal_.loads[0]->client->OnComplete(
      network::URLLoaderCompletionStatus(net::ERR_FAILED));
  tasks_.RunUntilIdle(); loader_->SetPriority(net::HIGHEST, 9);
  tasks_.RunUntilIdle(); EXPECT_TRUE(terminal_.loads[0]->priorities.empty());
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_FAILED);
  std::move(client_.deferred_ack).Run(); tasks_.RunUntilIdle();
  EXPECT_TRUE(acknowledged); EXPECT_EQ(client_.completions.size(), 1u);
}

TEST_F(KumoDomainFactoryTest, PendingAdmissionCannotStartThenAllowsExactlyOnce) {
  pending_ = true; Begin(); EXPECT_TRUE(terminal_.loads.empty());
  loader_->SetPriority(net::HIGHEST, 42);
  loader_->SetPriority(net::LOW, -1); tasks_.RunUntilIdle();
  Decide(true); ASSERT_EQ(terminal_.loads.size(), 1u);
  EXPECT_EQ(terminal_.loads[0]->priorities,
      (std::vector<std::pair<net::RequestPriority, int32_t>>{
          {net::HIGHEST, 42}, {net::LOW, -1}}));
}

TEST_F(KumoDomainFactoryTest, UnavailablePolicyRejectsWithoutTerminalContact) {
  available_ = false; Begin(); EXPECT_TRUE(terminal_.loads.empty());
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, ActualAdmissionTimeoutCannotLaterStartRequest) {
  timed_ = true; Begin(); EXPECT_TRUE(terminal_.loads.empty());
  tasks_.FastForwardBy(base::Seconds(15));
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
  timed_answer_ = true; tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_TRUE(terminal_.loads.empty()); EXPECT_EQ(client_.completions.size(), 1u);
}

TEST_F(KumoDomainFactoryTest, RequestFieldsHeadersUploadAndAnnotationAreUnchanged) {
  network::ResourceRequest request; request.url = GURL("https://allowed.invalid/upload");
  request.method = "POST"; request.referrer = GURL("https://referrer.invalid/");
  request.headers.SetHeader("X-Owned", "header");
  request.cors_exempt_headers.SetHeader("X-Trusted", "exempt");
  request.request_body = base::MakeRefCounted<network::ResourceRequestBody>();
  request.request_body->AppendBytes(std::vector<uint8_t>{1, 2, 3, 4});
  request.request_body->set_identifier(913);
  request.request_body->set_contains_sensitive_info(true);
  request.request_body->SetAllowHTTP1ForStreamingUpload(true);
  request.credentials_mode = network::mojom::CredentialsMode::kInclude;
  BeginRequest(request); ASSERT_EQ(terminal_.loads.size(), 1u);
  const auto& load = *terminal_.loads[0];
  // Mojo reconstructs the body object, so its pointer identity cannot survive
  // transport. Check every body field and byte before normalizing only that
  // pointer for ResourceRequest's remaining complete field comparison.
  ASSERT_TRUE(load.request.request_body);
  EXPECT_EQ(load.request.request_body->identifier(), request.request_body->identifier());
  EXPECT_EQ(load.request.request_body->contains_sensitive_info(),
            request.request_body->contains_sensitive_info());
  EXPECT_EQ(load.request.request_body->AllowHTTP1ForStreamingUpload(),
            request.request_body->AllowHTTP1ForStreamingUpload());
  ASSERT_EQ(load.request.request_body->elements()->size(), 1u);
  const auto& element = load.request.request_body->elements()->front();
  ASSERT_EQ(element.type(), network::DataElement::Tag::kBytes);
  EXPECT_EQ(element.As<network::DataElementBytes>().bytes(),
            (std::vector<uint8_t>{1, 2, 3, 4}));
  network::ResourceRequest normalized(load.request);
  normalized.request_body = request.request_body;
  EXPECT_TRUE(normalized.EqualsForTesting(request));
  EXPECT_EQ(load.request_id, 417);
  EXPECT_EQ(load.options, network::mojom::kURLLoadOptionSendSSLInfoWithResponse);
  EXPECT_EQ(load.annotation.unique_id_hash_code,
            TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code);
}

TEST_F(KumoDomainFactoryTest, CloneRetainsGateAfterOriginalFactoryCloses) {
  mojo::Remote<network::mojom::URLLoaderFactory> clone;
  factory_->Clone(clone.BindNewPipeAndPassReceiver());
  tasks_.RunUntilIdle(); factory_.reset(); factory_ = std::move(clone);
  Begin(GURL("https://blocked.invalid/from-clone"));
  EXPECT_TRUE(terminal_.loads.empty()); ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, ActiveLoadSurvivesAllFactoryReceiversClosing) {
  Begin(); ASSERT_EQ(terminal_.loads.size(), 1u); factory_.reset();
  tasks_.RunUntilIdle();
  network::URLLoaderCompletionStatus status(net::OK);
  terminal_.loads[0]->client->OnComplete(status); tasks_.RunUntilIdle();
  ASSERT_EQ(client_.completions.size(), 1u); EXPECT_EQ(client_.completions[0], status);
}

TEST_F(KumoDomainFactoryTest, BuilderRewrittenDestinationIsCheckedAtFinalGate) {
  RewritingFactory rewriter;
  network::URLLoaderFactoryBuilder builder;
  auto [receiver, remote] = builder.Append();
  rewriter.BindReceiver(std::move(receiver)); rewriter.target.Bind(std::move(remote));
  AppendDomainURLLoaderFactory(builder, Checker());
  factory_.reset(); factory_.Bind(std::move(builder).Finish<
      mojo::PendingRemote<network::mojom::URLLoaderFactory>>(terminal_.Bind()));
  Begin(); EXPECT_EQ(rewriter.calls, 1); EXPECT_TRUE(terminal_.loads.empty());
  ASSERT_EQ(checked_.size(), 1u); EXPECT_EQ(checked_[0].host(), "blocked.invalid");
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, InternalOverrideTailIsGatedWithoutChangingCORSFlags) {
  RewritingFactory rewriter;
  auto override = network::mojom::URLLoaderFactoryOverride::New();
  override->overriding_factory = rewriter.Bind();
  override->overridden_factory_receiver = rewriter.target.BindNewPipeAndPassReceiver();
  override->skip_cors_enabled_scheme_check = false;
  network::URLLoaderFactoryBuilder builder;
  AppendDomainURLLoaderFactory(builder, Checker(), override.get());
  EXPECT_EQ(builder.num_interceptors(), 0u);
  EXPECT_FALSE(override->skip_cors_enabled_scheme_check);
  ASSERT_TRUE(override->overriding_factory.is_valid());
  terminal_.BindReceiver(std::move(override->overridden_factory_receiver));
  factory_.reset(); factory_.Bind(std::move(override->overriding_factory));
  Begin(); EXPECT_EQ(rewriter.calls, 1); EXPECT_TRUE(terminal_.loads.empty());
  ASSERT_EQ(checked_.size(), 1u); EXPECT_EQ(checked_[0].host(), "blocked.invalid");
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, ListedRedirectIsBlockedBeforeExposureOrFollow) {
  Begin(); terminal_.loads[0]->Redirect(GURL("https://blocked.invalid/redirect"));
  tasks_.RunUntilIdle(); EXPECT_TRUE(client_.redirects.empty());
  EXPECT_EQ(terminal_.loads[0]->follows, 0); EXPECT_TRUE(terminal_.loads[0]->closed);
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, RedirectOverrideIsCheckedBeforeFollowing) {
  Begin(); terminal_.loads[0]->Redirect(GURL("https://allowed.invalid/redirect"));
  tasks_.RunUntilIdle(); ASSERT_EQ(client_.redirects.size(), 1u);
  loader_->FollowRedirect({}, GURL("https://blocked.invalid/override"));
  tasks_.RunUntilIdle(); EXPECT_EQ(terminal_.loads[0]->follows, 0);
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, AllowedRedirectPreservesOverrideAndHeaderUpdates) {
  Begin(); terminal_.loads[0]->Redirect(GURL("https://allowed.invalid/redirect"));
  tasks_.RunUntilIdle();
  network::HttpRequestHeadersUpdateParams headers;
  headers.removed_headers.push_back("X-Remove");
  headers.modified_headers.SetHeader("X-Change", "new");
  headers.modified_cors_exempt_headers.SetHeader("X-Exempt", "new-exempt");
  const GURL replacement("https://allowed.invalid/replacement");
  loader_->FollowRedirect(std::move(headers), replacement); tasks_.RunUntilIdle();
  const auto& load = *terminal_.loads[0];
  EXPECT_EQ(load.follows, 1); EXPECT_EQ(load.new_url, replacement);
  EXPECT_EQ(load.headers.removed_headers, (std::vector<std::string>{"X-Remove"}));
  EXPECT_EQ(load.headers.modified_headers.GetHeader("X-Change"), "new");
  EXPECT_EQ(load.headers.modified_cors_exempt_headers.GetHeader("X-Exempt"), "new-exempt");
}

TEST_F(KumoDomainFactoryTest, LivePolicyIsRecheckedWhenClientFollowsRedirect) {
  Begin(); terminal_.loads[0]->Redirect(GURL("https://allowed.invalid/redirect"));
  tasks_.RunUntilIdle(); ASSERT_EQ(client_.redirects.size(), 1u);
  available_ = false; loader_->FollowRedirect({}, std::nullopt);
  tasks_.RunUntilIdle(); EXPECT_EQ(terminal_.loads[0]->follows, 0);
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_BLOCKED_BY_CLIENT);
}

TEST_F(KumoDomainFactoryTest, CancellationWhilePendingCannotStartLateLoad) {
  pending_ = true; Begin(); loader_.reset(); tasks_.RunUntilIdle();
  Decide(true); EXPECT_TRUE(terminal_.loads.empty());
  EXPECT_TRUE(client_.completions.empty());
}

TEST_F(KumoDomainFactoryTest, ClientDisconnectCancelsDownstreamLoad) {
  Begin(); client_.Disconnect(); tasks_.RunUntilIdle();
  EXPECT_TRUE(terminal_.loads[0]->closed);
}

TEST_F(KumoDomainFactoryTest, DownstreamDisconnectCompletesExactlyOnce) {
  Begin(); terminal_.loads[0]->client.reset(); tasks_.RunUntilIdle();
  ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0].error_code, net::ERR_ABORTED);
  tasks_.RunUntilIdle(); EXPECT_EQ(client_.completions.size(), 1u);
}

TEST_F(KumoDomainFactoryTest, ResponseBodyMetadataSSLTimingsAndCallbacksAreUnchanged) {
  Begin(); auto& load = *terminal_.loads[0];
  auto hints = network::mojom::EarlyHints::New();
  hints->headers = network::mojom::ParsedHeaders::New();
  const auto expected_hints = hints.Clone();
  load.client->OnReceiveEarlyHints(std::move(hints));
  auto head = network::mojom::URLResponseHead::New();
  head->mime_type = "application/octet-stream"; head->content_length = 4;
  head->headers = net::HttpResponseHeaders::TryToCreate(
      "HTTP/1.1 200 OK\r\nX-Owned: unchanged\r\n\r\n");
  ASSERT_TRUE(head->headers);
  ASSERT_EQ(head->headers->GetNormalizedHeader("X-Owned"), "unchanged");
  head->request_start = base::TimeTicks::Now();
  head->response_start = head->request_start + base::Milliseconds(3);
  head->ssl_info = net::SSLInfo(); head->ssl_info->cert_status = 17;
  const auto request_start = head->request_start;
  const auto response_start = head->response_start;
  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer, consumer), MOJO_RESULT_OK);
  const std::vector<uint8_t> bytes{9, 8, 7, 6};
  ASSERT_EQ(producer->WriteAllData(bytes), MOJO_RESULT_OK); producer.reset();
  mojo_base::BigBuffer metadata{base::span<const uint8_t>(bytes)};
  load.client->OnReceiveResponse(std::move(head), std::move(consumer),
                                 std::move(metadata));
  bool ack = false;
  load.client->OnUploadProgress(3, 4, base::BindOnce(
      [](bool* value) { *value = true; }, &ack));
  load.client->OnTransferSizeUpdated(27);
  network::URLLoaderCompletionStatus status(net::OK);
  status.extended_error_code = 19; status.exists_in_cache = true;
  status.ssl_info = net::SSLInfo(); status.ssl_info->cert_status = 17;
  load.client->OnComplete(status); tasks_.RunUntilIdle();
  EXPECT_TRUE(client_.hints.Equals(expected_hints));
  ASSERT_TRUE(client_.head);
  EXPECT_EQ(client_.head->mime_type, "application/octet-stream");
  EXPECT_EQ(client_.head->content_length, 4);
  EXPECT_EQ(client_.head->headers->GetNormalizedHeader("X-Owned"), "unchanged");
  EXPECT_EQ(client_.head->request_start, request_start);
  EXPECT_EQ(client_.head->response_start, response_start);
  ASSERT_TRUE(client_.head->ssl_info);
  EXPECT_EQ(client_.head->ssl_info->cert_status, 17u);
  ASSERT_TRUE(client_.body.is_valid());
  base::span<const uint8_t> read;
  ASSERT_EQ(client_.body->BeginReadData(MOJO_BEGIN_READ_DATA_FLAG_NONE, read), MOJO_RESULT_OK);
  EXPECT_EQ(read, base::span<const uint8_t>(bytes));
  EXPECT_EQ(client_.body->EndReadData(read.size()), MOJO_RESULT_OK);
  ASSERT_TRUE(client_.metadata); EXPECT_EQ(client_.metadata->size(), bytes.size());
  EXPECT_EQ(base::span(*client_.metadata), base::span<const uint8_t>(bytes));
  EXPECT_TRUE(ack); EXPECT_EQ(client_.upload, (std::make_pair<int64_t, int64_t>(3, 4)));
  EXPECT_EQ(client_.transfer, 27); ASSERT_EQ(client_.completions.size(), 1u);
  EXPECT_EQ(client_.completions[0], status);
}

TEST_F(KumoDomainFactoryTest, NonHTTPFactoryRequestsRetainOriginalBehavior) {
  Begin(GURL("data:text/plain,owned"));
  EXPECT_TRUE(checked_.empty()); ASSERT_EQ(terminal_.loads.size(), 1u);
  EXPECT_EQ(terminal_.loads[0]->request.url, GURL("data:text/plain,owned"));
}
}  // namespace
}  // namespace kumo
