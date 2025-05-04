# C++ Project with Crypto++

This is a C++ project that implements the Siplified AES algorithm and compares the multiple modes of AES with the Cryptopp library.

## Project Structure

```
.
├── Makefile             # Build system configuration
├── README.md            # This file
├── build/               # Directory for compiled object files
├── lib/                 # Directory for libraries
│   └── cryptopp/        # Crypto++ library (downloaded automatically)
└── src/                 # Source code directory
```

## Prerequisites

- C++ compiler (g++ or compatible)
- Make
- curl or wget (for downloading Crypto++)
- unzip (for extracting Crypto++)

## Building

Simply run:

```bash
make
```

This will:
1. Create necessary directories
2. Download and build the Crypto++ library
3. Compile the project source files
4. Link everything into the final executable called `saes`

## Cleaning

To clean built project files:

```bash
make clean
```

To clean all built files including libraries:

```bash
make cleanall
```

## Usage

After building, run the executable:

```bash
./saes
```

## Additional Information

- The Crypto++ library is automatically downloaded and built (version 8.7.0)
- No manual installation of libraries is required

