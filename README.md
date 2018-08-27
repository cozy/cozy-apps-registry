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
- __[Access control and tokens](#access-control-and-tokens)__
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


```yaml
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
cozy-apps-registry gen-token --master Cozy -c cozy-registry.yml
```

Here we go, you have now an registry ready and running on the 8081 port.

> The `-c` options is always mandatory if you want to specify a config file like here.

### 5) Configure `cozy-stack` with the registry

On the `cozy-stack`, you have to add the new registry in the stack configuration file [`cozy.yaml`](https://github.com/cozy/cozy-stack/blob/master/docs/config.md#main-configuration-file) (registries property):

```yaml
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

##### For an application

To be publishable, your application requires some informations in its `manifest.webapp`, the manifest of a Cozy application. Here is an example for the application Drive:

<details>

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

</details>

##### For a connector

To be publishable, your konnector requires some informations in its `manifest.konnector`, the manifest of a Cozy konnector. Here is an example for the konnector `cozy-konnector-trainline`:

<details>

```json
{
  "version": "0.1.0",
  "name": "Trainline",
  "type": "konnector",
  "language": "node",
  "icon": "icon.svg",
  "slug": "trainline",
  "source": "git://github.com/konnectors/cozy-konnector-trainline.git#build",
  "editor": "Cozy",
  "vendorLink": "www.trainline.fr",
  "categories": ["transport"],
  "screenshots": ["screenshots/screenshot.png"],
  "fields": {
    "login": {
      "type": "text"
    },
    "password": {
      "type": "password"
    },
    "advancedFields": {
      "folderPath": {
        "advanced": true,
        "isRequired": false
      }
    }
  },
  "data_types": [
    "bill"
  ],
  "permissions": {...},
  "developer": {
    "name": "Cozy",
    "url": "https://cozy.io"
  },
  "langs": ["fr", "en"],
  "locales": {
    "fr": {
      "short_description": "Récupérer vos données Trainline dans votre Cozy",
      "long_description": "Ce fournisseur vous permettra de récupérer l'ensemble de vos factures Trainline dans votre Cozy."
    },
    "en": {
      "short_description": "Fetch your Trainline data in your Cozy",
      "long_description": "This provider will allow you to fetch all your Trainline bills in your Cozy."
    }
  }
}
```

</details>


##### Properties meaning (reference)

Here are all properties meaning for the manifest file (for webapp and konnectors) sorted alphabetically:

Field          | Description
---------------|-------------------------------------------------------------
`categories`     | array of categories for your apps (see authorized categories), it will be `['others']` by default if empty
`data_types`     | _(konnector specific)_ Array of the data type the konnector will manage
`developer`      | `name` and `url` for the developer
`editor`         | the editor's name to display on the cozy-bar (__REQUIRED__)
`fields`         | _(konnector specific)_ JSON object describing the fields need by the konnector. Used to generate a form. See [collect documentation](https://github.com/cozy/cozy-collect/blob/master/docs/konnector-manifest.md#fields-property)
`frequency`      | _(konnector specific)_ A human readable value between `monthly`, `weekly`, `daily`, indicating the interval of time between two runs of the konnector. Default : `weekly`.
`icon`           | path to the icon for the home (path in the build)
`intents`        | _(application specific)_ a list of intents provided by this app (see [cozy-stack intents doc](https://cozy.github.io/cozy-stack/intents.html) for more details)
`langs`          | Languages available in your app (can be different from locales)
`language`       | _(konnector specific)_ the konnector development language used (ex: `node`)
`license`        | [the SPDX license identifier](https://spdx.org/licenses/)
`locales`        | an object with language slug as property, each name property is an object of localized informations (see the second part below)
`messages`       | _(konnector specific)_ Array of message identifiers, which can be used by application to display information at known areas. See example in [collect documentation](https://github.com/cozy/cozy-collect/blob/master/docs/konnector-manifest.md#messages-example).
`name`           | the name to display on the home (__REQUIRED__)
`name_prefix`    | the prefix to display with the name
`oauth`          | _(konnector specific)_ JSON object containing oAuth information, like `scope`. If a manifest provides an `oauth` property, it is considered as an OAuth konnector.
`parameters`     | _(konnector specific)_ Additional parameters which should be passed to the konnector. Used for example for bank konnectors to pass a `bankId` parameter.
`permissions`    | a map of permissions needed by the app (see [see cozy-stack permissions doc ](https://cozy.github.io/cozy-stack/permissions.html) for more details)
`platforms`      | _(application specific)_ List of objects for platform native applications. For now there are only two properties: `type` (i.e. `'ios'` or `'linux'`) and the optional `url` to reach this application page.
`routes`         | _(application specific)_ a map of routes for the app (see [cozy-stack routes doc](https://cozy.github.io/cozy-stack/apps.html#routes) for more details) (__REQUIRED__)
`screenshots`    | an array of paths to the screenshots of the application (paths in the build)
`services`       | _(application specific)_ a map of the services associated with the app (see [cozy-stack services doc](https://cozy.github.io/cozy-stack/apps.html#services) for more details)
`slug`           | the default slug that should never change (alpha-numeric lowercase) (__REQUIRED__)
`source`         | where the files of the app can be downloaded (by default it will look for the branch `build`)
`tags`           | a list a tags describing your application and features (useful for indexing and search)
`time_interval`  | _(konnector specific)_ By defaults, konnector triggers are scheduled randomly between 00:00 AM and 05:00 AM. Those two values can be overwritten thanks to this property, by passing an array containing two values: first is the interval start hour, second is the interval end hour. Example: `[15, 21]` will randomly schedule the konnector trigger between 15:00 (03:00 PM) and 21:00 (09:00 PM).
`type`           | type of application (`konnector` or `webapp`) (__REQUIRED__)
`version`        | the current version number (__REQUIRED__)
`vendor_link`    | _(konnector specific)_ URL to editor or service website

Here are the properties that you can override using `locales` (we recommand to automatically build these properties according to your locales files if you're using a translating tool like `transifex`) :

Field             | Description
------------------|----------------------------------------------------------
name              | the name to display on the home
short_description | a short description of the application
long_description  | a longer and more complete description of the application
changes           | a description of your new version of the application or all changes since the last version, this part will be the changelog part of the application page in `cozy-store`
screenshots       | an array of paths to the screenshots of the application of this specific locale (paths in the build)


> __Notices:__
> - All images paths (`icon` and `screenshots`) should be relative to the build directory. For example, here, the `icon.svg` is stored in the build root directory and all `screenshots` are store in a folder `screenshots` in the build directory. Therefore, if you use a bundler (like webpack) be sure to know exactly where the bundler will store these assets in the build directory (and change it in the manifest if needed).
> - All properties in `locales` objects will override the matched property of the main `manifest.webapp` body, if a property is not found in `locales` it will fallback to the main body one.
> - We use to have the `en` locale as default one if the one wanted by the user doesn't exist. Be sure to have, at least, that locale complete with the name and all descriptions.
> - In your build files, this `manifest.webapp` file must be at the root.

### 2) Add a new application in the registry

#### Our official apps registry

Official registry URL: `https://apps-registry.cozycloud.cc`

In order to use our official repository, you need a token for a specific
editor. To do so, contact us directly at the address contact@cozycloud.cc
with a mail using the following title prefix: `[registry]` and provide us these folowing information (not changeable after):
- `slug` of your application
- `editor` name that you want

We will provide you with the correct token.

#### Custom registry

See the details below to know how to add a new application in a custom `cozy-apps-registry` instance (local or not).
<details>
> __Prequisites__:
> - For this step, you will need your editor token access generated when you created your editor (see [below](#4-create-an-editor)). You have to replace all `{{EDITOR_TOKEN}}` in this documentation by this token.
> - The communication with the registry is done through HTTP requests for now. So we will use the `curl` command line tool to register our application here.

Now you can add your application in the registry. This step is splitted in two septs:
  - Add a new application (without versions)
  - Add a version of the application

__:pushpin: A new application without registered version won't be displayed by the [`cozy-store` application](https://github.com/cozy/cozy-store).__

To add a new application, you have to do a `POST` request which all the informations needed to the route `registryAddress/registry`
with `registryAddress` your registry address (for example here `http://localhost:8081`).

Let's add the Collect application as example:

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
</details>

### 3) Add a new version of a registered application

#### Via [`cozy-app-publish`][cozy-app-publish] (highly recommanded)

__Here we will show the classical way to add a version using the manual mode of [`cozy-app-publish`][cozy-app-publish] as reference. But you may need to look at  the [Automation CI part](#automation-ci) of this documentation instead.__

> __Prequisites__:
> - For this step, you will need your editor token access generated when you created your editor (see [below](#4-create-an-editor)). You have to replace all `{{EDITOR_TOKEN}}` in this documentation by this token.
> - Don't forget to build your application first (run `yarn build`), `cozy-app-publish` will read the manifest from your build

Firstly, install the [`cozy-app-publish`][cozy-app-publish] package using
 `yarn` or `npm`:
```
yarn add cozy-app-publish --dev
```

> You can also install the package as a global package, but don't forget to update it frequently

Then use it to publish your application, here is an example for `collect`:

```
yarn cozy-app-publish \
--token {{EDITOR_TOKEN}} \
--build-url https://github.com/cozy/cozy-collect/archive/042cef26d9d33ea604fe4364eaab569980b500c9.tar.gz \
--manual-version 1.0.2-dev.042cef26d9d33ea604fe4364eaab569980b500c9
```

If you need more information about this tool, you can go to the official [`cozy-app-publish` documentation](https://github.com/cozy/cozy-app-publish).

#### Via `curl`

__Here we will show the classical way to add a version using `curl` as reference. But you may need to look at our dedicated tool [`cozy-app-publish`][cozy-app-publish] or the [Automation CI part](#automation-ci) of this documentation instead.__

> __Prequisites__:
> - For this step, you will need your editor token access generated when you created your editor (see [below](#4-create-an-editor)). You have to replace all `{{EDITOR_TOKEN}}` in this documentation by this token.
> - The communication with the registry is done through HTTP requests for now. So we will use the `curl` command line tool to register our application here.

To add a new application, you have to do a `POST` request which all the informations needed to the route `registryAddress/registry/:appSlug`
with `registryAddress` your registry address (for example here `http://localhost:8081`), `:appName` your application slug (here `drive`).

Let's add the version 1.0.1 of the Collect application as example:

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
    `myname/cozy-example`

You first need to add the token to your travis configuration file
`.travis.yml`. To do so, you need the [`travis` utility](https://github.com/travis-ci/travis.rb#installation) to encrypt its value.

```sh
$ travis encrypt REGISTRY_TOKEN={{EDITOR_TOKEN}} -r myname/cozy-example --org
Please add the following to your .travis.yml file:

  secure: "jUAjk..LOOOOONG_ENCRYPTED_STRING.....jdk89="
```

Like said, you need to add this block of ciphered data in the `.travis.yml` (if it's not already done automatically).
This will allow you to use the `REGISTRY_TOKEN` variable in your deployment
script.

Then, you can add the publish script in your `package.json` in order to be used by Travis:
```json
...
"publish:cozy": "git fetch origin ${DEPLOY_BRANCH:-build}:${DEPLOY_BRANCH:-build} && cozy-app-publish --token $REGISTRY_TOKEN --build-commit $(git rev-parse ${DEPLOY_BRANCH:-build})"
...
```

> This script will fetch your last commit from the `build` branch to publish to the registry. If you push a tag, be sure to wait the last `build` branch Travis build finished in order to have the real last commit to publish. 

Finally, you can add this script to your `.travis.yml` to publish your app using our publishing tool [`cozy-app-publish`][cozy-app-publish] during the `deploy` process:

```yml
...
before_deploy:
- yarn add cozy-app-publish
deploy:
  - provider: script
    repo: myname/cozy-example
    skip-cleanup: true
    script: export DEPLOY_BRANCH=build && yarn deploy && yarn publish:cozy
    on:
      branch: master
  - provider: script
    repo: myname/cozy-example
    skip-cleanup: true
    script: export DEPLOY_BRANCH=build && yarn publish:cozy
    on:
      tags: true
...
```

> __Important notices:__
> - A commit push to the branch master will publish your application in the `dev` channel of the registry.
> - A tag push (Github release) will publish a stable version (ex: `1.0.0`) or a beta version (ex: `1.0.1-beta2`) to the registry (automatically handled by the registry).
> - [`cozy-app-publish`][cozy-app-publish] will use the github archive URL computing to get the application tarball. If your applicaiton is not on Github, you may need to use the manual mode of the command.

### Access to our official apps registry

Official registry URL: `https://apps-registry.cozycloud.cc`

In order to use our official repository, you need a token for a specific
editor. To do so, contact us directly at the address contact@cozycloud.cc
with a mail using the following title prefix: `[registry]` and provide us these folowing information (not changeable after):
- `slug` of your application
- `editor` name that you want

We will provide you with the correct token.

## Access control and tokens

The read-only routes of the registry are all public and do not require any
access-contre. However routes allowing to create applications and versions have
access-control policies associated to them.

The registry has two types of access permissions, that are associated to two
different tokens:

  - **editor tokens**: these tokens give access to the publication of new versions
    on the registry, for a specific editor name, at these conditions:
    * the version's application must already exist in the registry
    * the version's application must have the same "editor" value as the token
  - **master tokens**: these tokens are allowed to create and register new
    applications on the registry, and associate them with an existing editor
    name. They also have the same accesses as the editor tokens.

Editor tokens can be specific to one or more applications names that they are
allowed to publish.

In order to create tokens, the binary offers a `gen-token` command-line. Here
are some examples to illustrates some usages:

```sh
# Generating tokens
  # generate an editor token for the editor "cozy", for any application
  $ cozy-apps-registry gen-token cozy
  # generate an editor token for the editor "cozy" expiring after 30 days
  $ cozy-apps-registry gen-token cozy --max-age 30d
  # generate an editor token for the editor "cozy" for application "collect" and "drive"
  $ cozy-apps-registry gen-token cozy --apps collect,drive
  # generate a master token associated with the editor "cozy" expiring after 30 days
  $ cozy-apps-registry gen-token cozy --master --max-age 30d

# Verifying tokens
  # verify the editor token "XXX" for the editor "cozy"
  $ cozy-apps-registry verify-token cozy "XXX"
  # verify the master token "XXX" associated with the editor "cozy"
  $ cozy-apps-registry verify-token cozy "XXX" --master

# Revoking tokens
  # revoke all editors tokens for the cozy editor
  $ cozy-apps-registry revoke-tokens cozy
  # revoke all master tokens associated with the cozy editor
  $ cozy-apps-registry revoke-tokens cozy --master
```

## Maintenance

In order to set/unset an application into maintenance mode, the binary offers
a `maintenance` command-line. Here are some examples of how to use it:

```sh
# Activate maintenance mode for the application 'bank' of space 'myspace'
# Available flagged options:
#  --infra            specify a maintenance specific to our infra
#  --no-manual-exec   specify a maintenance disallowing manual execution
#  --short            specify a short maintenance
$ cozy-apps-registry maintenance activate bank --space myspace

# Deactivate maintenance mode for the application 'bank' of space 'myspace'
$ cozy-apps-registry maintenance deactivate bank --space myspace
```

Or using a cURL request and a master token:

```sh
curl -XPUT \
  -H"Authorization: Token $COZY_REGISTRY_ADMIN_TOKEN" \
  -H"Content-Type: application/json" \
  -d'{"flag_infra_maintenance": false,"flag_short_maintenance": false,"flag_disallow_manual_exec": false,"messages": {"fr": {"long_message": "Bla bla bla","short_message": "Bla"},"en": {"long_message": "Yadi yadi yada","short_message": "Yada"}}}' \
  https://apps-registry.cozycloud.cc/myspace/registry/maintenance/bank/activate

curl -XPUT \
  -H"Authorization: Token $COZY_REGISTRY_ADMIN_TOKEN" \
  https://apps-registry.cozycloud.cc/registry/maintenance/bank/deactivate
```

## Application confidence grade / labelling

The confidence grade of an applications can be specified by specifying the
`data_usage_commitment` and `data_usage_commitment_by` fields of the
application document.

Possible values for these properties are:

* `data_usage_commitment_by`: specify a technical commitment from the
  application editor:
  - `user_ciphered`: technical commitment that the user's data is encrypted
    and can only be known by him.
  - `user_reserved`: commitment that the data is only used for the user, to
    directly offer its service.
  - `none`: no commitment
* `data_usage_commitment_by`: specify what entity is taking the commitment:
  - `cozy`: the commitment is taken by cozy
  - `editor`: the commitment is taken by the application's editor
  - `none`: no commitment is taken

To do that, a command line and admin API are available, and be used as follow:

```sh
$ cozy-apps-registry modify-app banks --space my_space --data-usage-commitment user_reserved --data-usage-commitment-by editor
```

Or using a cURL request and a master token:

```
curl -XPATCH \
  -H"Authorization: Token $COZY_REGISTRY_ADMIN_TOKEN" \
  -H"Content-Type: application/json" \
  -d'{"data_usage_commitment": "user_reserved", "data_usage_commitment_by": "editor"}
  https://apps-registry.cozycloud.cc/my_space/registry/banks
```

## Community

You can reach the Cozy Community by:

- Chatting with us on IRC [#cozycloud on Freenode][freenode]
- Posting on our [Forum][forum]
- Posting issues on the [Github repos][github]
- Say Hi! on [Twitter][twitter]


[cozy]: https://cozy.io "Cozy Cloud"
[cozy-app-publish]: https://github.com/cozy/cozy-app-publish
[freenode]: http://webchat.freenode.net/?randomnick=1&channels=%23cozycloud&uio=d4
[forum]: https://forum.cozy.io/
[github]: https://github.com/cozy/
[twitter]: https://twitter.com/cozycloud
