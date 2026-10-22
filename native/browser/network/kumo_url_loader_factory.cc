// Copyright 2026 Kumo authors. All rights reserved.
#include "chrome/browser/kumo/network/kumo_url_loader_factory.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "net/base/net_errors.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/self_deleting_url_loader_factory.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/cpp/url_loader_factory_builder.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace kumo {
namespace {

class DomainRequest final : public network::mojom::URLLoader,
                            public network::mojom::URLLoaderClient {
 public:
  static void Create(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id, uint32_t options,
      const network::ResourceRequest& request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation,
      scoped_refptr<network::SharedURLLoaderFactory> target,
      DomainAdmission admission) {
    auto owned = std::make_unique<DomainRequest>(
        request_id, options, request, std::move(client), annotation,
        std::move(target), std::move(admission));
    auto* raw = owned.get();
    raw->owner_ = mojo::MakeSelfOwnedReceiver(std::move(owned),
                                             std::move(receiver));
    raw->Start();
  }

  DomainRequest(int32_t request_id, uint32_t options,
                const network::ResourceRequest& request,
                mojo::PendingRemote<network::mojom::URLLoaderClient> client,
                const net::MutableNetworkTrafficAnnotationTag& annotation,
                scoped_refptr<network::SharedURLLoaderFactory> target,
                DomainAdmission admission)
      : request_id_(request_id), options_(options), request_(request),
        annotation_(annotation), target_(std::move(target)),
        admission_(std::move(admission)), client_(std::move(client)) {
    // Priority messages can safely queue on this unconnected pipe while the
    // initial admission is pending; no downstream request has started yet.
    downstream_receiver_ = loader_.BindNewPipeAndPassReceiver();
    loader_.set_disconnect_handler(base::BindOnce(
        &DomainRequest::Disconnected, weak_.GetWeakPtr()));
    client_.set_disconnect_handler(base::BindOnce(
        &DomainRequest::ClientDisconnected, weak_.GetWeakPtr()));
  }
  ~DomainRequest() override = default;

  void FollowRedirect(network::HttpRequestHeadersUpdateParams headers,
                      const std::optional<GURL>& new_url) override {
    if (state_ != State::kAwaitingFollow) {
      Complete(network::URLLoaderCompletionStatus(net::ERR_UNEXPECTED));
      return;
    }
    state_ = State::kCheckingFollow;
    const GURL destination = new_url.value_or(redirect_url_);
    Check(destination, base::BindOnce(&DomainRequest::FollowAllowed,
                                    weak_.GetWeakPtr(), std::move(headers),
                                    new_url));
  }
  void SetPriority(net::RequestPriority priority, int32_t intra_priority) override {
    if (state_ == State::kCompleted || !loader_.is_bound()) return;
    loader_->SetPriority(priority, intra_priority);
  }

  void OnReceiveEarlyHints(network::mojom::EarlyHintsPtr hints) override {
    client_->OnReceiveEarlyHints(std::move(hints));
  }
  void OnReceiveResponse(network::mojom::URLResponseHeadPtr head,
                         mojo::ScopedDataPipeConsumerHandle body,
                         std::optional<mojo_base::BigBuffer> metadata) override {
    client_->OnReceiveResponse(std::move(head), std::move(body),
                               std::move(metadata));
  }
  void OnReceiveRedirect(const net::RedirectInfo& info,
                         network::mojom::URLResponseHeadPtr head) override {
    if (state_ != State::kLoading) {
      Complete(network::URLLoaderCompletionStatus(net::ERR_UNEXPECTED));
      return;
    }
    state_ = State::kCheckingRedirect;
    redirect_url_ = info.new_url;
    Check(info.new_url, base::BindOnce(&DomainRequest::RedirectAllowed,
                                     weak_.GetWeakPtr(), info, std::move(head)));
  }
  void OnUploadProgress(int64_t current, int64_t total,
                        OnUploadProgressCallback ack) override {
    ++pending_upload_acks_;
    client_->OnUploadProgress(current, total, base::BindOnce(
        &DomainRequest::UploadAcknowledged, weak_.GetWeakPtr(), std::move(ack)));
  }
  void OnTransferSizeUpdated(int32_t difference) override {
    client_->OnTransferSizeUpdated(difference);
  }
  void OnComplete(const network::URLLoaderCompletionStatus& status) override {
    Complete(status);
  }

 private:
  enum class State {
    kCheckingStart, kLoading, kCheckingRedirect, kAwaitingFollow,
    kCheckingFollow, kCompleted
  };
  void Start() {
    Check(request_.url, base::BindOnce(&DomainRequest::StartAllowed,
                                     weak_.GetWeakPtr()));
  }
  void Check(const GURL& url, base::OnceCallback<void(bool)> callback) {
    if (!url.SchemeIsHTTPOrHTTPS()) {
      std::move(callback).Run(true);
      return;
    }
    if (!admission_) {
      std::move(callback).Run(false);
      return;
    }
    admission_.Run(url, std::move(callback));
  }
  void StartAllowed(bool allowed) {
    if (state_ == State::kCompleted) return;
    if (!allowed) { Block(); return; }
    state_ = State::kLoading;
    auto downstream_client = client_receiver_.BindNewPipeAndPassRemote();
    client_receiver_.set_disconnect_handler(base::BindOnce(
        &DomainRequest::Disconnected, weak_.GetWeakPtr()));
    target_->CreateLoaderAndStart(
        std::move(downstream_receiver_), request_id_, options_, request_,
        std::move(downstream_client), annotation_);
  }
  void RedirectAllowed(net::RedirectInfo info,
                       network::mojom::URLResponseHeadPtr head, bool allowed) {
    if (state_ == State::kCompleted) return;
    if (!allowed) { Block(); return; }
    state_ = State::kAwaitingFollow;
    client_->OnReceiveRedirect(info, std::move(head));
  }
  void FollowAllowed(network::HttpRequestHeadersUpdateParams headers,
                     std::optional<GURL> new_url, bool allowed) {
    if (state_ == State::kCompleted) return;
    if (!allowed) { Block(); return; }
    state_ = State::kLoading;
    // Preserve the override and all header changes. The existing network
    // implementation continues to enforce same-origin and redirect security.
    loader_->FollowRedirect(std::move(headers), new_url);
  }
  void Block() {
    Complete(network::URLLoaderCompletionStatus(net::ERR_BLOCKED_BY_CLIENT));
  }
  void Disconnected() {
    Complete(network::URLLoaderCompletionStatus(net::ERR_ABORTED));
  }
  void ClientDisconnected() { Close(); }
  void UploadAcknowledged(OnUploadProgressCallback ack) {
    std::move(ack).Run();
    --pending_upload_acks_;
    if (state_ == State::kCompleted && pending_upload_acks_ == 0) Close();
  }
  void Complete(const network::URLLoaderCompletionStatus& status) {
    if (state_ == State::kCompleted) return;
    state_ = State::kCompleted;
    client_->OnComplete(status);
    if (status.error_code != net::OK) {
      loader_.reset();
      downstream_receiver_.reset();
    }
    // Do not lose an upload-progress reply that is still in flight. Otherwise
    // close completed control pipes promptly; the forwarded body pipe has an
    // independent lifetime. Client disconnect always cancels this relay.
    if (pending_upload_acks_ == 0) Close();
  }
  void Close() {
    // Invalidate pending policy replies before destroying pipes. Closing the
    // self-owned receiver also cancels the downstream load and all callbacks.
    weak_.InvalidateWeakPtrs();
    owner_->Close();
  }

  const int32_t request_id_;
  const uint32_t options_;
  network::ResourceRequest request_;
  const net::MutableNetworkTrafficAnnotationTag annotation_;
  scoped_refptr<network::SharedURLLoaderFactory> target_;
  DomainAdmission admission_;
  mojo::Remote<network::mojom::URLLoaderClient> client_;
  mojo::Receiver<network::mojom::URLLoaderClient> client_receiver_{this};
  mojo::Remote<network::mojom::URLLoader> loader_;
  mojo::PendingReceiver<network::mojom::URLLoader> downstream_receiver_;
  mojo::SelfOwnedReceiverRef<network::mojom::URLLoader> owner_;
  GURL redirect_url_;
  State state_ = State::kCheckingStart;
  size_t pending_upload_acks_ = 0;
  base::WeakPtrFactory<DomainRequest> weak_{this};
};

class DomainFactory final : public network::SelfDeletingURLLoaderFactory {
 public:
  DomainFactory(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver,
                mojo::PendingRemote<network::mojom::URLLoaderFactory> target,
                DomainAdmission admission, base::SelfDeletingPassKey key)
      : network::SelfDeletingURLLoaderFactory(std::move(receiver), key),
        target_(base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
            std::move(target))), admission_(std::move(admission)) {}
  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id, uint32_t options,
      const network::ResourceRequest& request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation) override {
    DomainRequest::Create(std::move(receiver), request_id, options, request,
                          std::move(client), annotation, target_, admission_);
  }
 private:
  ~DomainFactory() override = default;
  scoped_refptr<network::SharedURLLoaderFactory> target_;
  DomainAdmission admission_;
};
}  // namespace

void AppendDomainURLLoaderFactory(network::URLLoaderFactoryBuilder& builder,
                                 DomainAdmission admission,
                                 network::mojom::URLLoaderFactoryOverride*
                                     factory_override) {
  if (factory_override &&
      factory_override->overridden_factory_receiver.is_valid()) {
    // DevTools can replace the network service's internal factory, inside its
    // CORS/security wrapper. Put this gate on the override's final target pipe
    // after URL rewriting. Do not change the outer factory or any CORS flags.
    mojo::PendingRemote<network::mojom::URLLoaderFactory> target;
    auto network_receiver = target.InitWithNewPipeAndPassReceiver();
    base::MakeSelfDeleting<DomainFactory>(
        std::move(factory_override->overridden_factory_receiver),
        std::move(target), std::move(admission));
    factory_override->overridden_factory_receiver = std::move(network_receiver);
    return;
  }
  auto [receiver, remote] = builder.Append();
  base::MakeSelfDeleting<DomainFactory>(std::move(receiver), std::move(remote),
                                        std::move(admission));
}
}  // namespace kumo
