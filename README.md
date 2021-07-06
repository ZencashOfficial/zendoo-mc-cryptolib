# zendoo-mc-cryptolib


`zendoo-mc-cryptolib` is an FFI library crate that exposes the [ginger-lib](https://github.com/HorizenOfficial/ginger-lib) Rust components needed to support [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") in mainchain.

In particular it exposes interfaces to:

* handle the finite field that is the alphabet of the zk Proving System
* call the Poseidon hash function
* use a Poseidon-based, in-memory, random access Merkle Tree
* verify a SNARK proof, the cryptographic proof included in Zendoo "backward transfer" certificates


**Please note: the code is in development. No guarantees are provided about its security and functionality**


## Build guide

The library can be built by using Cargo:
 
```
	cargo build
```  
Note: You need `clang` installed.
There are a few Rust tests that can be executed still with the usual Cargo command:  

```
	cargo test --all-features
```  


## Examples

In the [example folder](examples) you can find a few C++ tests and examples of invocation of Rust functions. You can compile and execute them via the provided *Makefile*.

## Contributing

Contributions are welcomed! Bug fixes and new features can be initiated through GitHub pull requests. To speed the code review process, please adhere to the following guidelines:

* Follow Horizen repositories' *code of conduct*
* Follow Horizen repositories' *styling guide* 
* Please gpg sign your commits 
* Please make sure you push your pull requests to the development branch

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

## License

The code is licensed under the following license:

 * MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in ginger-lib by you shall be licensed as above, without any additional terms or conditions.

[![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)
