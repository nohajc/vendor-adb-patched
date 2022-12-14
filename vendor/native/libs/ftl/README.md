# FTL

FTL is a template library shared by SurfaceFlinger and InputFlinger, inspired by
and supplementing the C++ Standard Library. The intent is to fill gaps for areas
not (yet) covered—like cache-efficient data structures and lock-free concurrency
primitives—and implement proposals that are missing or experimental in Android's
libc++ branch. The design takes some liberties with standard compliance, notably
assuming that exceptions are disabled.

## Tests

    atest ftl_test

## Style

- Based on [Google C++ Style](https://google.github.io/styleguide/cppguide.html).
- Informed by [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines).

Naming conventions are as follows:

- `PascalCase`
    - Types and aliases, except standard interfaces.
    - Template parameters, including non-type ones.
- `snake_case`
    - Variables, and data members with trailing underscore.
    - Functions, free and member alike.
    - Type traits, with standard `_t` and `_v` suffixes.
- `kCamelCase`
    - Enumerators and `constexpr` constants with static storage duration.
- `MACRO_CASE`
    - Macros, with `FTL_` prefix unless `#undef`ed.

Template parameter packs are named with the following convention:

    typename T, typename... Ts
    typename Arg, typename... Args

    std::size_t I, std::size_t... Is
    std::size_t Size, std::size_t... Sizes

The `details` namespace contains implementation details.
