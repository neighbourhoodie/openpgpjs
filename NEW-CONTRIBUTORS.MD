# Guide for New Contributors <!-- omit from toc -->

👋 **First off! Hello, and a warm welcome to the OpenPGP.js project!**

We’re delighted that you’re interested in participating, and we want to make it as pleasant and simple as we can, whether you want to send a one-off pull request or you want to become part of the team in the long run.

**If you’re new here and interested in any form of contribution, this guide is for you.**

**Contents:**

- [Getting your Bearings](#getting-your-bearings)
- [Who are we and what is OpenPGP.js?](#who-are-we-and-what-is-openpgpjs)
- [Who can help?](#who-can-help)
- [How do you get Started?](#how-do-you-get-started)


## Getting your Bearings

We’ve got a bunch of helpful resources you might be interested in:

- There’s a [public gitter chat](https://app.gitter.im/#/room/#openpgpjs_openpgpjs:gitter.im), which is a good place for establishing first contact with the project
- **Our [Guide for Contributors](/CONTRIBUTING.md), which details  topics such as project processes, code and commit conventions, expectations for PRs, as well as documentation on dev setup and testing.**
- A [high level overview of the OpenPGP.js repositories](/PROJECT_STRUCTURE.md), explaining how the individual repos in this organisation relate to each other
- The [Code of Conduct](/CODE_OF_CONDUCT.md) we operate by, and which you are also expected to adhere to

## Who are we and what is OpenPGP.js?

[OpenPGP.js](https://openpgpjs.org/) is a JavaScript implementation of the [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol. It implements [RFC4880](https://tools.ietf.org/html/rfc4880) and parts of [RFC4880bis](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10).

This project aims to provide an Open Source OpenPGP library in JavaScript so it can be used on virtually every device. Instead of other implementations that are aimed at using native code, OpenPGP.js is meant to bypass this requirement (i.e. people will not have to install gpg on their machines in order to use the library). The idea is to implement all the needed OpenPGP functionality in a JavaScript library that can be reused in other projects that provide browser extensions or server applications. It should allow you to sign, encrypt, decrypt, and verify any kind of text - in particular e-mails - as well as managing keys.

This project is maintained by [Proton Mail](https://proton.me/blog/openpgpjs-email-encryption) and is supported by the EU’s Horizon 2020 programme.

OpenPGP.js is built by [a variety of people](https://github.com/orgs/openpgpjs/people), but there are a couple you’ll run into more frequently, and who can be considered the core of the project:

- [twiss](https://github.com/twiss) (Daniel Huigens)
- [larabr](https://github.com/larabr)

## Who can help?

This _is_ cryptography-heavy JavaScript software, so those skills are especially relevant. However, an Open Source project such as this one has a wide range of needs, and there are a lot of opportunities to help:

- There are usually some non-cryptography related JS (and TS!) tasks
- You can expand or improve the test suite
- You can take the project for a test drive and update the dev setup documentation for your platform (see [CONTRIBUTING.md](/CONTRIBUTING.md))
- You can improve the various documentation resources in general, for example by looking for [documentation issues](https://github.com/openpgpjs/openpgpjs/issues?q=is%3Aissue+is%3Aopen+label%3ADocumentation), or just picking something to expand upon, edit or check for typos
- You can improve the build process
- You can do manual tests and UI/UX evaluations of features or tools and help improve their usability
- You can improve or maintain [our website](https://openpgpjs.org/)
- You can evangelize for the project: present or talk about OpenPGP.js in your company, local tech meetup, youtube channel, or similar circles

## How do you get Started?

TODO:
- Openpgp basics
- dev setup
- say hello on gitter
-




