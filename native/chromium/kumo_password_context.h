#ifndef KUMO_PASSWORD_CONTEXT_H_
#define KUMO_PASSWORD_CONTEXT_H_

#include <cstdint>

namespace content { class RenderFrameHost; }
namespace kumo {
// Kept below Chromium's unbounded menu range. The overlay rejects collisions.
inline constexpr int kFillFromApplePasswordsCommand = 57200;
bool CanFillFromApplePasswords(content::RenderFrameHost* frame, uint64_t field_id);
void FillFromApplePasswords(content::RenderFrameHost* frame,
                           uint64_t field_id,
                           bool is_password);
}  // namespace kumo

#endif
