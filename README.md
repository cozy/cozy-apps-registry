# cozy-apps-registry

### What's Cozy?

<div align="center">
  <a href="https://cozy.io">
    <img src="https://cdn.rawgit.com/cozy/cozy-site/master/src/images/cozy-logo-name-horizontal-blue.svg" alt="cozy" height="48" />
  </a>
 </div>
 </br>

[Cozy] is a platform that brings all your web services in the same private space.  With it, your webapps and your devices can share data easily, providing you with a new experience. You can install Cozy on your own hardware where no one's tracking you.


## Table of contents

- __[What about this repository?](#what-about-this-repository)__
- __[Develop with `cozy-apps-registry`](#how-to-develop-with-a-cozy-apps-registry-working-in-local-environment)__
    - [1) Install and configure the local `cozy-apps-registry`](#1-install-and-configure-the-local-cozy-apps-registry)
    - [2) Configure the registry with `cozy-registry.yml`](#2-configure-the-registry-with-cozy-registryyml)
    - [3) Run the registry to serve the apps](#3-run-the-registry-to-serve-the-apps)
    - [4) Create an editor](#4-create-an-editor)
    - [5) Configure `cozy-stack` with the registry](#5-configure-cozy-stack-with-the-registry)
- __[Publish your application on the registry](#publish-your-application-on-the-registry)__
    - [1) Prepare your application](#1-prepare-your-application)
    - [2) Add a new application in the registry](#2-add-a-new-application-in-the-registry)
    - [3) Add a new version of a registered application](#3-add-a-new-version-of-a-registered-application)
    - [Automation (CI)](#automation-ci)
    - [Access to our official apps registry](#access-to-our-official-apps-registry)
- __[Community](#community)__


## What about this repository?

The `cozy-apps-registry` is a go project that implements the [registry
API](https://github.com/cozy/cozy-stack/blob/master/docs/registry.md)
described to work with the [cozy-stack](https://github.com/cozy/cozy-stack).

It requires Couchdb 2.0 to work properly.


## How to develop with a `cozy-apps-registry` working in local environment

Before starting, you will need to have a couchdb running already. That can be the one used by the local `cozy-stack` if you have one. For this tutorial, couchdb will be running on the default port 5984.

### 1) Install and configure the local `cozy-apps-registry`

Since this is a golang project, you can install it using `go` with the followed command:

```shell
go get -u github.com/cozy/cozy-apps-registry
cd $GOPATH/src/github.com/cozy/cozy-apps-registry/
```

Then you will need a session secret key to run the registry (this key will be store in the `sessionsecret.key` file of your working directory) using a password:

```shell
cozy-apps-registry gen-session-secret --passphrase sessionsecret.key
```

> This password is important, you will need it to run the `cozy-apps-registry` again later. If you lose it, you will have to start again these steps.

### 2) Configure the registry with `cozy-registry.yml`

Before running the registry, you have to configure it correctly. Don't worry, here is the `.yaml` file to copy and paste in your `cozy-registry.yml` (should be in the root folder of `cozy-registry/`):

> :bulb: You can find an [example of this configuration file](cozy-registry.example.yml) at the root of the directory.


```yml
# server host (serve command) - flag --host
host: "localhost"
# server port (serve command) - flag --port
port: 8081

couchdb:
  # CouchDB server url - flag --couchdb-url
  url: http://localhost:5984
  # CouchDB user - flag --couchdb-user
  user: ''
  # CouchDB password - flag --couchdb-password
  password: ''
  # CouchDB prefix for the registries databases - flag --couchdb-prefix
  prefix: registry1

# Path to the session secret file containing the master secret to generate
# session token.
#
# Should be generated with the "gen-session-secret" command.
session-secret: sessionsecret.key
```

Feel free to change it if some configurations change in your case (the couchdb user, the server parameters or the databases prefix for example).

> __Notices :__
> - Here the generated session token (step 1) is stored in the `sessionsecret.key` file of the working directory, this is so the value of the property `session-secret` at the end of the configuration file.
> - By default, the local couchdb allow all admin accesses without creating users, so there is no user and password here. But if an admin user has been created, you have to use the properties `user` and `password` in the `couchdb` part to provide these informations.

### 3) Run the registry to serve the apps

Run the registry using this followed command (here our configuration file is a `cozy-registry.yml` in the current working directory):

```shell
cozy-apps-registry serve -c cozy-registry.yml
```

At this step, you should have a cozy-apps-registry running and ready for the development.

If you runnig the registry for the first time you can see the next steps to create a new editor and to configure your local `cozy-stack` to run with this new registry.

> The `-c` options is always mandatory if you want to specify a config file like here.

### 4) Create an editor

This step is required to submit new applications in the registry.
In another terminal, run these commands to create an editor (the one that will submit the application(s)) and generate an access token:

```shell
cozy-apps-registry add-editor Cozy -c cozy-registry.yml
cozy-apps-registry gen-token Cozy -c cozy-registry.yml
```

Here we go, you have now an registry ready and running on the 8081 port.

> The `-c` options is always mandatory if you want to specify a config file like here.

### 5) Configure `cozy-stack` with the registry

On the `cozy-stack`, you have to add the new registry in the stack configuration file [`cozy.yaml`](https://github.com/cozy/cozy-stack/blob/master/docs/config.md#main-configuration-file) (registries property):

```yml
...
registries:
  default:
    - http://localhost:8081/
...
```

Now restart your local `cozy-stack` to take this new configuration in consideration (stop and run again `cozy-stack serve`) and you're ready to work with the `cozy-apps-registry`!

## Publish your application on the registry

If you need more details about the registry you can go to [the official registry documentation](https://cozy.github.io/cozy-stack/registry.html)

__:warning: Important:__ In this whole documentation, by the term `application`, we mean a web application or a konnector. Indeed, for the registry, all entities are applications and they can be either `webapp` or `konnector` type.

### 1) Prepare your application

To be publishable, your application requires some informations in its `manifest.webapp`, the manifest of a Cozy application. here is an example for the application Drive:

```json
{
  "name": "Drive",
  "name_prefix": "Cozy",
  "slug": "drive",
  "icon": "drive.svg",
  "type": "webapp",
  "locales": {
    "en": {
      "name": "Drive",
      "short_description": "The drive application, files manager for Cozy.",
      "long_description": "Drive allows you to manage all your files on your Cozy in a an easy way. You can add/upload new files, remove, rename or share them. You can also sort all your files in folders in a way as easy as on your computer.",
      "changes": "## New features\n\nNow you can __share__ your files using a specific link or a cozy email :tada:"
    },
    "fr": {
      "name": "Drive",
      "short_description": "L'application drive, gestionnaire de fichier pour Cozy.",
      "long_description": "Drive vous permets de gérer très facilement tous vos fichiers sur votre Cozy. Vous pouvez ajouter/télécharger de nouveaux fichiers, les supprimer, les renommer ou encore les partager. Vous pouvez aussi les triers dans dans des fichiers aussi simplement que sur votre ordinateur.",
      "changes": "## Nouvelle fonctionnalités\n\nMaintenant vous pouvez partager vos fichiers par lien ou par e-mail Cozy :tada:"
    }
  },
  "langs": ["en", "fr"],
  "platforms": [
    {
      "type": "ios",
      "url": "#"
    },
    {
      "type": "android",
      "url": "#"
    }
  ],
  "categories": ["cozy"],
  "source": "https://github.com/cozy/cozy-drive.git@build",
  "editor": "Cozy",
  "developer": {
    "name": "Cozy",
    "url": "https://cozy.io"
  },
  "version": "1.0.0",
  "licence": "AGPL-3.0",
  "screenshots": ["screenshots/screenshot1.png", "screenshots/screenshot2.png", "screenshots/screenshot3.png", "screenshots/screenshot4.png"],
  "tags": [
    "share",
    "folder",
    "files",
    "filesystem"
  ],
  "permissions": {...},
  "services": {...},
  "routes": {...},
  "intents": {...}
}
```

Here are all properties meaning:

Field          | Description
---------------|-------------------------------------------------------------
name           | the name to display on the home
name_prefix    | the prefix to display with the name
slug           | the default slug that should never change (alpha-numeric lowercase)
icon           | path to the icon for the home (path in the build)
type           | type of application (`konnector` or `webapp`)
Languages      | for konnectors only, the konnector development language used (ex: `node`)
locales        | an object with language slug as property, each name property is an object of localized informations (see the second part below)
langs          | Languages available in your app (can be different from locales)
platforms      | List of objects for platform native applications. For now there are only two properties: `type` (i.e. `'ios'` or `'linux'`) and the optional `url` to reach this application page.
categories     | array of categories for your apps (see authorized categories), it will be `['others']` by default if empty
source         | where the files of the app can be downloaded (by default it will look for the branch `build`)
editor         | the editor's name to display on the cozy-bar
developer      | `name` and `url` for the developer
version        | the current version number
license        | [the SPDX license identifier](https://spdx.org/licenses/)
screenshots    | an array of path sto the screenshots of the application (paths in the build)
tags          | a list a tags describing your application and features (useful for indexing and search)
permissions    | a map of permissions needed by the app (see [see cozy-stack permissions doc ](https://cozy.github.io/cozy-stack/permissions.html) for more details)
services       | a map of the services associated with the app (see [cozy-stack services doc](https://cozy.github.io/cozy-stack/apps.html#services) for more details)
routes         | a map of routes for the app (see [cozy-stack routes doc](https://cozy.github.io/cozy-stack/apps.html#routes) for more details)
intents        | a list of intents provided by this app (see [cozy-stack intents doc](https://cozy.github.io/cozy-stack/intents.html) for more details)

Here are the properties that you can override using `locales` (we recommand to automatically build these properties according to your locales files if you're using a translating tool like `transifex`) :

Field             | Description
------------------|----------------------------------------------------------
name              | the name to display on the home
short_description | a short description of the application
long_description  | a longer and more complete description of the application
changes           | a description of your new version of the application or all changes since the last version, this part will be the changelog part of the application page in `cozy-store`


> __Notices:__
> - All images paths (`icon` and `screenshots`) should be relative to the build directory. For example, here, the `icon.svg` is stored in the build root directory and all `screenshots` are store in a folder `screenshots` in the build directory. Therefore, if you use a bundler (like webpack) be sure to know exactly where the bundler will store these assets in the build directory (and change it in the manifest if needed).
> - All properties in `locales` objects will override the matched property of the main `manifest.webapp` body, if a property is not found in `locales` it will fallback to the main body one.
> - We use to have the `en` locale as default one if the one wanted by the user doesn't exist. Be sure to have, at least, that locale complete with the name and all descriptions.
> - In your build files, this `manifest.webapp` file must be at the root.

### 2) Add a new application in the registry

> __Prequisites__:
> - For this step, you will need your editor token access generated when you created your editor (see [below](#4-create-an-editor)). You have to replace all `{{EDITOR_TOKEN}}` in this documentation by this token.
> - The communication with the registry is done through HTTP requests for now. So we will use the `curl` command line tool to register our application here.

Now you can add your application in the registry. This step is splitted in two septs:
  - Add a new application (without versions)
  - Add a version of the application

__:pushpin: A new application without registered version won't be displayed by the [`cozy-store` application](https://github.com/cozy/cozy-store).__

To add a new application, you have to do a `POST` request which all the informations needed to the route `registryAddress/registry`
with `registryAddress` your registry address (for example here `http://localhost:8081`).

Let's add the Drive application with the previous manifest as example:

```shell
# {{EDITOR_TOKEN}} -> your generated editor access token
curl -X "POST" "http://localhost:8081/registry" \
     -H "Authorization: Token {{EDITOR_TOKEN}}" \
     -H "Content-Type: application/json" \
     -d $'{
  "slug": "collect",
  "type": "webapp",
  "editor": "{{EDITOR}}"
}'
```

Field          | Description
---------------|-------------------------------------------------------------
slug           | your application unique ID
type           | kind of application (it can be only `webapp` or `konnector`)
editor         | Name of the editor matching the `{{EDITOR_TOKEN}}`

__:warning: Here the `slug` is the unique ID of the application in the registry, so it can't be changed after the application is already registered.__

### 3) Add a new version of a registered application

> __Prequisites__:
> - For this step, you will need your editor token access generated when you created your editor (see [below](#4-create-an-editor)). You have to replace all `{{EDITOR_TOKEN}}` in this documentation by this token.
> - The communication with the registry is done through HTTP requests for now. So we will use the `curl` command line tool to register our application here.

To add a new application, you have to do a `POST` request which all the informations needed to the route `registryAddress/registry/:appSlug`
with `registryAddress` your registry address (for example here `http://localhost:8081`), `:appName` your application slug (here `drive`).

Let's add the version 1.0.0 of the Drive application as example:

```shell
# {{EDITOR_TOKEN}} -> your generated editor access token
curl -X "POST" "http://localhost:8081/registry/collect" \
     -H "Authorization: Token {{EDITOR_TOKEN}}" \
     -H "Content-Type: application/json" \
     -d $'{
  "url": "https://github.com/cozy/cozy-collect/archive/1.0.1.tar.gz",
  "sha256": "96212bf53ab618808da0a92c7b6d9f2867b1f9487ba7c1c29606826b107041b5",
  "version": "1.0.1",
  "type": "webapp",
  "editor": "{{EDITOR}}"
}'
```

Field          | Description
---------------|-------------------------------------------------------------
url           | the archive source of your application, it will be downloaded and checked with the sha256 property
sha256        | the sha256 hash of your source archive matching the archive in `url` (see the notice below)
version       | version of the application, must match the one in the manifest (see the notice below)
type           | kind of application (it can be only `webapp` or `konnector`)
editor         | Name of the editor matching the `{{EDITOR_TOKEN}}`

> __:warning: Important notices:__
> - The version must match the one in the `manifest.webapp` file for stable release. For beta (X.X.X-betaX) or dev releases (X.X.X-dev.hash256), the version before the cyphen must match the one in the `manifest.webapp`.
> - For better integrity, the `sha256` provided must match the sha256 of the archive provided in `url`. If it's not the case, that will be considered as an error and the version won't be registered.

### Automation (CI)

The following tutorial explains how to connect your continuous integration
based on Travis to automatically publish new versions on the apps registry.

In this tutorial, we assume:

  - you have a token allowing you to publish applications for your `editor`:
    `{{EDITOR_TOKEN}}`
  - you are working on a repository plugged on travis and named on github
    `cozy/cozy-example`

You first need to add the token to your travis configuration file
`.travis.yml`. To do so, you need the [`travis` utility](https://github.com
/travis-ci/travis.rb#installation) to encrypt its value.

```sh
$ travis encrypt REGISTRY_TOKEN={{EDITOR_TOKEN}} --add -r cozy/cozy-example
Please add the following to your .travis.yml file:

  secure: "jUAjk..LOOOOONG_ENCRYPTED_STRING.....jdk89="
```

Like said, you need to add this block of ciphered data in the `.travis.yml`.
This will allow you to use the `REGISTRY_TOKEN` variable in your deployment
script.

Then you can adapt this script as your [`after_deploy`, `after_success` or `script`](https://docs.travis-ci.com/user/customizing-the-build#The-Build-Lifecycle) property like:

```yml
...
after_success:
- bash publish_script.sh
...
```

> __Important notices:__
> - The `.travis.yml` which will run this script must be in your build target directory if your want that Travis run it only on CI from the build branch update.
> - Same thing for the script (here `publish_script.sh`), don't forget to make it available in your build directory.

It contains environment variables that you can adapt as your need (or create new ones):
  - `COZY_APP_VERSION`: the version string of the deployed version
  - `COZY_BUILD_URL`: the URL of the deployed tarball for your application
  - `COZY_BUILD_BRANCH`: the name of the build branch from which the script creates dev releases

Here is an example of script that can be run on Travis when there is new update on the `build` branch:

```bash
#!/bin/bash
set -e

# Environnment variables:
#   COZY_APP_VERSION: the version string of the deployed version
#   COZY_APP_SLUG: the slug string of the deployed application
#   COZY_BUILD_URL: the URL of the deployed tarball for your application
#   COZY_BUILD_BRANCH: the name of the build branch from which the script
#                      creates dev releases

[ -z "${COZY_BUILD_BRANCH}" ] && COZY_BUILD_BRANCH="build"
[ -z "${REGISTRY_EDITOR}" ] && REGISTRY_EDITOR="Cozy"
[ -z "${REGISTRY_URL}"] && REGISTRY_URL="https://staging-apps-registry.cozycloud.cc/registry"

# don't publish on pull requests
if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then
    echo "No deployment: in pull-request"
    exit 0
fi

# Run this publishing script only on CI from the build branch
# and at each update of this branch
if [ "${TRAVIS_BRANCH}" != "${COZY_BUILD_BRANCH}" ]; then
    printf 'No deployment: not in %s branch (TRAVIS_BRANCH=%s TRAVIS_TAG=%s)\n' "${COZY_BUILD_BRANCH}" "${TRAVIS_BRANCH}" "${TRAVIS_TAG}"
    exit 0
fi

# find app manifest
manfile=$(find "${TRAVIS_BUILD_DIR}" \( -name "manifest.webapp" -o -name "manifest.konnector" \) | head -n1)

# if git tag, version = tag, else, version = versionFromManifest-dev.sha256
if [ -z "${COZY_APP_VERSION}" ]; then
    if [ -n "${TRAVIS_TAG}" ]; then
        COZY_APP_VERSION="${TRAVIS_TAG}"
    else
        COZY_APP_VERSION="$(jq -r '.version' < "${manfile}")-dev.${TRAVIS_COMMIT}"
    fi
fi

# get app slug from the manifest
if [ -z "${COZY_APP_SLUG}" ]; then
    COZY_APP_SLUG="$(jq -r '.slug' < "${manfile}")"
fi

# if git tag, get archive url from the tag,
# else, get archive url from the the commit hash
if [ -z "${COZY_BUILD_URL}" ]; then
    url="https://github.com/${TRAVIS_REPO_SLUG}/archive"
    if [ -n "${TRAVIS_TAG}" ]; then
        COZY_BUILD_URL="${url}/${TRAVIS_TAG}.tar.gz"
    else
        COZY_BUILD_URL="${url}/${TRAVIS_COMMIT}.tar.gz"
    fi
fi

# get the sha256 hash from the archive from the url
shasum=$(curl -sSL --fail "${COZY_BUILD_URL}" | shasum -a 256 | cut -d" " -f1)

printf 'Publishing version "%s" from "%s" (%s) to %s\n' "${COZY_APP_VERSION}" "${COZY_BUILD_URL}" "${shasum}" "${REGISTRY_URL}/${COZY_APP_SLUG}"

# publish the application
curl -sS --fail -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Token ${REGISTRY_TOKEN}" \
    -d "{\"editor\": \"${REGISTRY_EDITOR}\", \"version\": \"${COZY_APP_VERSION}\", \"url\": \"${COZY_BUILD_URL}\", \"sha256\": \"${shasum}\", \"type\": \"webapp\"}" \
    "${REGISTRY_URL}/${COZY_APP_SLUG}"
```

__This script will:__
  - Publish a new stable version when git tag (ex: `1.0.0`).
  - Publish a new beta version when git tag with `-beta` inside (ex: `1.0.1-beta2`). (The registry will automatically detect a beta release if there is the term `beta` in the version)
  - Publish a new dev version at each new CI build on the `COZY_BUILD_BRANCH` which is `build` here.

### Access to our official apps registry

In order to access to our official repository, you need a token for a specific
editor. To do so, concact us directly at the address contact@cozycloud.cc
with a mail using the following title prefix: `[registry]` and
precising the name of the editor of your application.

We will provide you with the correct token.


## Community

You can reach the Cozy Community by:

- Chatting with us on IRC [#cozycloud on Freenode][freenode]
- Posting on our [Forum][forum]
- Posting issues on the [Github repos][github]
- Say Hi! on [Twitter][twitter]


[cozy]: https://cozy.io "Cozy Cloud"
[freenode]: http://webchat.freenode.net/?randomnick=1&channels=%23cozycloud&uio=d4
[forum]: https://forum.cozy.io/
[github]: https://github.com/cozy/
[twitter]: https://twitter.com/cozycloud
