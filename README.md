# TenzoXAuthenticationCPP

Lightweight C++ library for authentication and license management.
Includes **login, registration, license validation, and version checks**.

**Website:** [https://txabeta.netlify.app/](https://txabeta.netlify.app/)

## Usage

Include the `include` and `lib` folders in your project and link required libraries.

```cpp
#include "tenzoxauth.h"

TenzoAuth auth("1.0", "app1", "SecretKey");
auth.Login("username", "password");
```

## Credits

* [cURL](https://curl.se/) – for HTTP requests
* [JSON for Modern C++](https://github.com/nlohmann/json) – for JSON parsing

## License

**Educational Use Only** – Learn from the code, but **do not modify, distribute, or use maliciously**.
