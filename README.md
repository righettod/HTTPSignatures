# HTTPSignatures Burp Suite Extension

[![build-artifact](https://github.com/righettod/HTTPSignatures/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/righettod/HTTPSignatures/actions/workflows/maven.yml)

## Objective

This fork of the [original project](https://github.com/nccgroup/HTTPSignatures) add the following features:
* Support for the signature using the algorithm **HS2019** of the [RFC9421](https://datatracker.ietf.org/doc/rfc9421/) `HTTP Message Signatures`.
* Support for the signature using JSON Web Signature ([RFC7515](https://datatracker.ietf.org/doc/rfc7515/)) used by [OpenFinance](https://www.berlin-group.org/openfinance-downloads) (document `openFinance Framework - Implementation Guidelines - Protocol Functions and Security Measures`) .
* Add more debug traces.
* Use caching for the private key and its related X.509 certificate to reduce local IO for each request to sign.

## Burp support

Tested with the version `2024.x` of [Burp Professional](https://portswigger.net/burp/pro) and developed using [Intellij IDEA Community Edition](https://www.jetbrains.com/idea/download).

## Release

See [here](https://github.com/righettod/HTTPSignatures/actions) to download a build of the extension (extension jar file is attached to the build job).

## Original README

See [here](README-original.md).

## Resources

* https://www.berlin-group.org/openfinance-downloads
* https://c2914bdb-1b7a-4d22-b792-c58ac5d6648e.usrfiles.com/ugd/c2914b_0bc6a7d6cd6641c5a4a430d09c50f2fd.pdf
* https://medium.com/syntaxa-tech-blog/open-banking-message-signing-b4ab4f7f92d1
* https://developer.revolut.com/docs/guides/build-banking-apps/tutorials/work-with-json-web-signatures
* https://datatracker.ietf.org/doc/rfc9421/
* https://datatracker.ietf.org/doc/rfc7515
