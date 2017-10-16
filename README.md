cozy-apps-registry
==================

## What is Cozy?

![Cozy Logo](https://raw.githubusercontent.com/cozy/cozy-stack/master/assets/images/happycloud.png)

[Cozy](https://cozy.io) is a platform that brings all your web services in the
same private space. With it, your web apps and your devices can share data
easily, providing you with a new experience. You can install Cozy on your own
hardware where no one profiles you.


## And what about this repository?

The cozy-apps-registry is a go project that implement the [registry
API](https://github.com/cozy/cozy-stack/blob/master/docs/registry.md)
described to work with the [cozy-stack](https://github.com/cozy/cozy-stack).

It requires Couchdb 2.0 to work properly.


## Hack

```sh
$ go get -u github.com/cozy/cozy-apps-registry
$ cozy-apps-registry gen-session-secret --passphrase false
$ cozy-apps-registry serve
```

To generate a token:

```
$ cozy-apps-registry add-editor my-editor
$ cozy-apps-registry gen-token my-editor
```


## Configuration file

See the [example](cozy-registry.example.yml) at the root of the directory.


## Community

You can reach the Cozy Community by:

* Chatting with us on IRC #cozycloud on irc.freenode.net
* Posting on our [Forum](https://forum.cozy.io)
* Posting issues on the [Github repos](https://github.com/cozy/)
* Mentioning us on [Twitter](https://twitter.com/mycozycloud)


## License

Cozy is developed by Cozy Cloud and distributed under the AGPL v3 license.

