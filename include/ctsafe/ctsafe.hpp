// ctsafe — comparisons that do not leak through timing, and erasure the
// optimizer is not allowed to delete.
//
// Two bugs, both older than most of the code that still contains them:
//
//   memcmp(mac, expected, 16) == 0
//     memcmp returns as soon as two bytes differ. An attacker who can time the
//     call learns how many leading bytes they guessed right, and recovers the
//     tag one byte at a time. (CWE-208.)
//
//   memset(key, 0, sizeof key);   // at the end of a function
//     The compiler can see the buffer is dead afterwards and delete the store
//     entirely, leaving the key in memory for a core dump or a later
//     allocation to find. (CWE-14.)
//
// Neither needs a clever fix. They need a fix that the compiler is not
// permitted to undo, which is what this header is.
//
// Header-only, C++17, no allocation, no exceptions.
#ifndef CTSAFE_CTSAFE_HPP
#define CTSAFE_CTSAFE_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>

// Which barrier is available. GCC and Clang accept an empty asm block with a
// memory clobber; MSVC has an intrinsic that constrains the optimizer the same
// way. A compiler with neither is handled, and says so.
#if defined(__GNUC__) || defined(__clang__)
#define CTSAFE_BARRIER_ASM 1
#elif defined(_MSC_VER)
#define CTSAFE_BARRIER_MSVC 1
#include <intrin.h>
#endif

// Which routine erase() calls. Where the platform ships a function for this,
// that function carries the promise not to be optimized away, and using it is
// better than arguing with the optimizer from portable code. The last branch is
// the fallback, and it is named in erase_backend_name() rather than assumed.
//
// Defining CTSAFE_NO_WINDOWS_H keeps <windows.h> out of the translation unit at
// the cost of taking the fallback there.
#if defined(_WIN32) && !defined(CTSAFE_NO_WINDOWS_H)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#define CTSAFE_ERASE_SECUREZEROMEMORY 1
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
#define CTSAFE_ERASE_EXPLICIT_BZERO 1
#elif defined(__STDC_LIB_EXT1__)
#define CTSAFE_ERASE_MEMSET_S 1
#else
#define CTSAFE_ERASE_VOLATILE 1
#endif

namespace ctsafe {

/// A byte-wide mask: 0xFF for true, 0x00 for false. Masks are how a branch is
/// avoided — you compute both answers and select one arithmetically.
using mask = std::uint8_t;

namespace detail {

/// Stop the optimizer from reasoning about a value across this point.
///
/// The empty asm block is opaque to the compiler: it must assume the memory is
/// read, so it cannot prove a preceding store is dead. This is the same
/// mechanism the benchmark libraries use to keep a result alive.
inline void keep(const volatile void* p) noexcept {
#if defined(CTSAFE_BARRIER_ASM)
    asm volatile("" : : "r"(p) : "memory");
#elif defined(CTSAFE_BARRIER_MSVC)
    (void)p;
    _ReadWriteBarrier();
#else
    // Neither an asm block nor an intrinsic. The volatile accesses stand on
    // their own, which is weaker but not nothing, and the fallback is
    // deliberate rather than accidental.
    (void)p;
#endif
}

/// Recognises the shapes a caller already holds — std::array, std::vector,
/// std::string, std::string_view, and std::span on C++20 — by the two members
/// they all provide. Byte-sized elements only, so a wider element type cannot
/// quietly turn into a byte count that is too small.
template <typename, typename = void>
struct is_byte_range : std::false_type {};

template <typename T>
struct is_byte_range<T, std::void_t<decltype(std::declval<const T&>().size()),
                                   std::enable_if_t<sizeof(*std::declval<const T&>().data()) == 1>>>
    : std::true_type {};

}  // namespace detail

/// 0xFF when a == b, 0x00 otherwise. No branch on the values.
[[nodiscard]] inline mask eq(std::uint8_t a, std::uint8_t b) noexcept {
    // x is zero exactly when the bytes match; the shift spreads the sign of
    // (x - 1) across the whole byte without comparing anything.
    std::uint8_t x = static_cast<std::uint8_t>(a ^ b);
    return static_cast<mask>((static_cast<std::uint16_t>(x) - 1u) >> 8);
}

/// Select a when m is 0xFF and b when m is 0x00, without branching.
[[nodiscard]] inline std::uint8_t select(mask m, std::uint8_t a, std::uint8_t b) noexcept {
    return static_cast<std::uint8_t>((a & m) | (b & static_cast<std::uint8_t>(~m)));
}

/// A non-owning span of bytes: a pointer and a length that travel together.
///
/// It converts from whatever the caller already has, so the length is read off
/// the buffer rather than retyped at the call site — the mistake that turns a
/// tag comparison into an overread.
class byte_view {
public:
    byte_view() noexcept = default;

    byte_view(const void* data, std::size_t size) noexcept
        : data_(static_cast<const std::uint8_t*>(data)), size_(size) {}

    template <typename T, std::size_t N, typename = std::enable_if_t<sizeof(T) == 1>>
    byte_view(const T (&array)[N]) noexcept
        : data_(reinterpret_cast<const std::uint8_t*>(array)), size_(N) {}

    template <typename Range, typename = std::enable_if_t<detail::is_byte_range<Range>::value>>
    byte_view(const Range& range) noexcept
        : data_(reinterpret_cast<const std::uint8_t*>(range.data())), size_(range.size()) {}

    [[nodiscard]] constexpr const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

/// Compare two buffers of the same length in time that does not depend on
/// where — or whether — they differ.
///
/// Both buffers must hold at least `length` bytes; nothing here can check that,
/// which is why the span overload below exists.
[[nodiscard]] inline bool equals(const void* left, const void* right, std::size_t length) noexcept {
    const auto* a = static_cast<const std::uint8_t*>(left);
    const auto* b = static_cast<const std::uint8_t*>(right);

    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < length; ++i) {
        difference = static_cast<std::uint8_t>(difference | (a[i] ^ b[i]));
    }
    // Every byte was read before anything is decided.
    detail::keep(&difference);
    return difference == 0;
}

/// The same comparison over two spans, which carry their own lengths.
///
/// A size mismatch answers false before a byte is read. The length is not
/// secret: buffers of different sizes are a structural error, not a guess to
/// protect, and reading the shorter one past its end would be worse than the
/// leak being avoided.
[[nodiscard]] inline bool equals(byte_view left, byte_view right) noexcept {
    if (left.size() != right.size()) return false;
    return equals(left.data(), right.data(), left.size());
}

/// True when every byte is zero, in constant time.
[[nodiscard]] inline bool is_zero(const void* data, std::size_t length) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint8_t any = 0;
    for (std::size_t i = 0; i < length; ++i) any = static_cast<std::uint8_t>(any | bytes[i]);
    detail::keep(&any);
    return any == 0;
}

/// Which routine erase() ends up calling in this build.
enum class erase_backend {
    secure_zero_memory,  ///< Windows, via SecureZeroMemory.
    explicit_bzero,      ///< glibc >= 2.25, OpenBSD, FreeBSD.
    memset_s,            ///< C11 Annex K, where the implementation offers it.
    volatile_stores,     ///< The portable fallback: volatile stores plus a barrier.
};

/// The backend this build selected. Reported rather than guessed, because the
/// strength of the guarantee differs between the rows.
[[nodiscard]] constexpr erase_backend erase_backend_used() noexcept {
#if defined(CTSAFE_ERASE_SECUREZEROMEMORY)
    return erase_backend::secure_zero_memory;
#elif defined(CTSAFE_ERASE_EXPLICIT_BZERO)
    return erase_backend::explicit_bzero;
#elif defined(CTSAFE_ERASE_MEMSET_S)
    return erase_backend::memset_s;
#else
    return erase_backend::volatile_stores;
#endif
}

/// The same answer as a printable name, so a program can log what it got.
[[nodiscard]] constexpr const char* erase_backend_name() noexcept {
#if defined(CTSAFE_ERASE_SECUREZEROMEMORY)
    return "SecureZeroMemory";
#elif defined(CTSAFE_ERASE_EXPLICIT_BZERO)
    return "explicit_bzero";
#elif defined(CTSAFE_ERASE_MEMSET_S)
    return "memset_s";
#elif defined(CTSAFE_BARRIER_ASM) || defined(CTSAFE_BARRIER_MSVC)
    return "volatile stores + compiler barrier";
#else
    return "volatile stores (no barrier available)";
#endif
}

/// Overwrite a buffer with zeroes in a way the compiler may not remove.
///
/// Where the platform ships a routine whose whole purpose is to survive
/// dead-store elimination, that routine is called. Where it does not, the
/// stores go through a `volatile` pointer, which a conforming implementation
/// must emit. Either way a barrier follows, so the buffer cannot be treated as
/// dead across the call.
inline void erase(void* data, std::size_t length) noexcept {
    if (length == 0) return;
#if defined(CTSAFE_ERASE_SECUREZEROMEMORY)
    SecureZeroMemory(data, length);
#elif defined(CTSAFE_ERASE_EXPLICIT_BZERO)
    ::explicit_bzero(data, length);
#elif defined(CTSAFE_ERASE_MEMSET_S)
    (void)::memset_s(data, length, 0, length);
#else
    auto* bytes = static_cast<volatile std::uint8_t*>(data);
    for (std::size_t i = 0; i < length; ++i) bytes[i] = 0;
#endif
    detail::keep(data);
}

/// Erase an object by type, so the size cannot be got wrong.
template <typename T>
inline void erase_object(T& object) noexcept {
    static_assert(!__is_polymorphic(T), "erasing a polymorphic object would destroy its vtable pointer");
    erase(&object, sizeof(T));
}

}  // namespace ctsafe

#endif  // CTSAFE_CTSAFE_HPP
