# cozy-apps-registry

[![go.dev reference](https://pkg.go.dev/badge/github.com/cozy/cozy-apps-registry)](https://pkg.go.dev/github.com/cozy/cozy-apps-registry)
[![Build Status](https://github.com/cozy/cozy-apps-registry/workflows/CI/badge.svg)](https://github.com/cozy/cozy-apps-registry/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/cozy/cozy-apps-registry)](https://goreportcard.com/report/github.com/cozy/cozy-apps-registry)

### What's Cozy?

<div align="center">
  <a href="https://cozy.io">
    <img src="https://cdn.rawgit.com/cozy/cozy-site/master/src/images/cozy-logo-name-horizontal-blue.svg" alt="cozy" height="48" />
  </a>
 </div>
 </br>

[Cozy] is a platform that brings all your web services in the same private space.  With it, your webapps and your devices can share data easily, providing you with a new experience. You can install Cozy on your own hardware where no one's tracking you.


## Table of contents

- [cozy-apps-registry](#cozy-apps-registry)
    - [What's Cozy?](#whats-cozy)
  - [Table of contents](#table-of-contents)
  - [What about this repository?](#what-about-this-repository)
  - [How to develop with a `cozy-apps-registry` working in local environment](#how-to-develop-with-a-cozy-apps-registry-working-in-local-environment)
    - [1) Install and configure the local `cozy-apps-registry`](#1-install-and-configure-the-local-cozy-apps-registry)
    - [2) Configure the registry with `cozy-registry.yml`](#2-configure-the-registry-with-cozy-registryyml)
    - [3) Run the registry to serve the apps](#3-run-the-registry-to-serve-the-apps)
    - [4) Create an editor](#4-create-an-editor)
    - [5) Configure `cozy-stack` with the registry](#5-configure-cozy-stack-with-the-registry)
  - [Publish your application on the registry](#publish-your-application-on-the-registry)
    - [1) Define your application manifest](#1-define-your-application-manifest)
        - [Properties meaning (reference)](#properties-meaning-reference)
      - [Available manifest’s features list :](#available-manifests-features-list-)
        - [Translated manifest fields](#translated-manifest-fields)
        - [Application terms](#application-terms)
        - [Konnectors folders handling](#konnectors-folders-handling)
        - [Konnectors fields property](#konnectors-fields-property)
        - [Konnectors message property](#konnectors-message-property)
        - [Categories and Data types](#categories-and-data-types)
    - [2) Add a new application in the registry](#2-add-a-new-application-in-the-registry)
      - [Our official apps registry](#our-official-apps-registry)
      - [Custom registry](#custom-registry)
    - [3) Add a new version of a registered application](#3-add-a-new-version-of-a-registered-application)
      - [Via `cozy-app-publish` (highly recommanded)](#via-cozy-app-publish-highly-recommanded)
      - [Via `curl`](#via-curl)
    - [Spaces & Virtual Spaces](#spaces--virtual-spaces)
      - [Spaces](#spaces)
        - [Create a space](#create-a-space)
        - [Remove a space](#remove-a-space)
      - [Virtual Spaces](#virtual-spaces)
    - [Automation (CI)](#automation-ci)
  - [Access control and tokens](#access-control-and-tokens)
  - [Maintenance](#maintenance)
  - [Import/export](#importexport)
  - [Application confidence grade / labelling](#application-confidence-grade--labelling)
  - [Universal links](#universal-links)
    - [Configuration](#configuration)
      - [Config file](#config-file)
      - [Files](#files)
    - [Usage](#usage)
  - [Budget-Insight web auth](#budget-insight-web-auth)
  - [Community](#community)


## What about this repository?

The `cozy-apps-registry` is a go project that implements the [registry
API](https://github.com/cozy/cozy-stack/blob/master/docs/registry.md)
described to work with the [cozy-stack](https://github.com/cozy/cozy-stack).

To work properly, it requires:

- Couchdb >= 2.3
- Redis
- Openstack Object Storage (Swift)

## How to develop with a `cozy-apps-registry` working in local environment

Before starting, you will need to have a couchdb running already. That can be the one used by the local `cozy-stack` if you have one. For this tutorial, couchdb will be running on the default port 5984.

You also must have redis and an OpenStack Object Storage (Swift) up and running. You can follow install instructions on [the official website](https://docs.openstack.org/swift/latest/install/index.html)

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

Before running the registry, you have to configure it correctly. Don't worry, here is the yaml file to copy and paste in your `cozy-registry.yml` (should be in the root folder of `cozy-apps-registry/`):

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

swift:
  # Swift auth URL (provided by keystone)
  auth_url: http://172.28.128.3/identity/v3
  # Swift username
  username: admin
  # Swift password
  api_key: secret
  # Endpoint type (public/admin/internal)
  endpointy_type: public
  # Project name
  tenant: demo
  # Swift domain
  domain: default

# Path to the session secret file containing the master secret to generate
# session token.
#
# Should be generated with the "gen-session-secret" command.
session-secret: sessionsecret.key
```

Feel free to change it if some configurations change in your case (the couchdb user, the server parameters or the databases prefix for example).

> __Notices:__
>
> - Here the generated session token (step 1) is stored in the `sessionsecret.key` file of the working directory, this is so the value of the property `session-secret` at the end of the configuration file.
> - By default, the local couchdb allow all admin accesses without creating users, so there is no user and password here. But if an admin user has been created, you have to use the properties `user` and `password` in the `couchdb` part to provide these informations.

It's also possible to use env variables for configuration. You can take the key from the configuration file and add the `COZY_REGISTRY` prefix. For example, you can run:

```shell
COZY_REGISTRY_PORT=8081 cozy-apps-registry serve
```

There is also the `REGISTRY_SESSION_PASS` env variable for the password for the session secret.

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

If you need more details about the registry you can go to [the official registry documentation](https://docs.cozy.io/en/cozy-stack/registry/)

__:warning: Important:__ In this whole documentation, by the term `application`, we mean a web application or a konnector. Indeed, for the registry, all entities are applications and they can be either `webapp` or `konnector` type.

### 1) Define your application manifest

To be publishable, your application requires some informations in its `manifest.webapp`, the manifest of a Cozy application.

You can find an example of manifest for an application [in Cozy-Drive](https://github.com/cozy/cozy-drive/blob/master/src/drive/targets/manifest.webapp) and one for a konnector [in cozy-konnector-trainline](https://github.com/konnectors/cozy-konnector-trainline/blob/master/manifest.konnector).

Most properties are common to both applications and konnectors but platforms, screenshots, services, routes and intents are only used in applications. Properties oauth, data_types, doctypes, fields, frequency, language, messages, parameters, time_interval, uuid and vendor_link ar only used in konnectors.


##### Properties meaning (reference)

Here are all properties meaning for the manifest file (for webapp and konnectors) sorted alphabetically:

Field              | Description
-------------------|---------------------------------------------------------------------------------------------------
`aggregator`       | Object containing aggregator data. Typically `{ accountId: 'aggregator-service' }`.
`categories`       | array of categories for your apps (see authorized categories), it will be `['others']` by default if empty
`data_types`       | _(konnector specific)_ Array of the data type the konnector will manage
`developer`        | `name` and `url` for the developer
`editor`           | the editor's name to display on the cozy-bar (__REQUIRED__)
`fields`           | _(konnector specific)_ JSON object describing the fields need by the konnector (__except folder path__). Used to generate a form. See [below](#konnectors-fields-property)
`folders`          | _(konnector specific)_ A list of folders required by the konnector to store files according to datatype (see the [specific documentation below](#konnectors-folders-handling))
`frequency`        | _(konnector specific)_ A human readable value between `monthly`, `weekly`, `daily`, indicating the interval of time between two runs of the konnector. Default: `weekly`.
`icon`             | path to the icon for the home (path in the build)
`intents`          | _(application specific)_ a list of intents provided by this app (see [cozy-stack intents doc](https://docs.cozy.io/en/cozy-stack/intents/) for more details)
`langs`            | Languages available in your app (can be different from locales)
`language`         | _(konnector specific)_ the konnector development language used (ex: `node`)
`license`          | [the SPDX license identifier](https://spdx.org/licenses/)
`locales`          | an object with language slug as property, each name property is an object of localized informations (see the second part below)
`manifest_version` | The current manifest version used. This is a versioning for the manifest and allow better retrocompatiblity when processing app manifest
`messages`         | _(konnector specific)_ Array of message identifiers, which can be used by application to display information at known areas. See [example below](#konnectors-message-property).
`mobile`           | _(application specific)_ JSON object containing information about app's mobile version (see [cozy-stack routes doc](https://docs.cozy.io/en/cozy-stack/apps/#mobile) for more details)
`name`             | the name to display on the home (__REQUIRED__)
`name_prefix`      | the prefix to display with the name
`oauth`            | _(konnector specific)_ JSON object containing oAuth information, like `scope`. If a manifest provides an `oauth` property, it is considered as an OAuth konnector. Note: scope can be a string or an array. If it is an array, its values will be joined with a space. A `false` or `null` value in scope will remove any scope parameter in the request sent to the oauth provider.
`parameters`       | _(konnector specific)_ Additional parameters which should be passed to the konnector. Used for example for bank konnectors to pass a `bankId` parameter.
`partnership`      | an object to provide informations (to display in the Store for example) about a partnership related to the application (`icon` `description`, `name` and `domain`). It can also be used to trigger alternative konnector connection policies for some vendors (see the [budget-insight konnector policy in cozy-harvest](https://github.com/cozy/cozy-libs/blob/065f7e2f3e89efa3b6b49e4ba7f9e20f92825560/packages/cozy-harvest-lib/src/services/budget-insight.js#L123)).
`permissions`      | a map of permissions needed by the app (see [see cozy-stack permissions doc ](https://docs.cozy.io/en/cozy-stack/permissions/) for more details)
`platforms`        | _(application specific)_ List of objects for platform native applications. For now there are only two properties: `type` (i.e. `'ios'` or `'linux'`) and the optional `url` to reach this application page.
`routes`           | _(application specific)_ a map of routes for the app (see [cozy-stack routes doc](https://docs.cozy.io/en/cozy-stack/apps/#routes) for more details) (__REQUIRED__)
`screenshots`      | an array of paths to the screenshots of the application (paths in the build)
`services`         | _(application specific)_ a map of the services associated with the app (see [cozy-stack services doc](https://docs.cozy.io/en/cozy-stack/apps/#services) for more details)
`slug`             | the default slug that should never change (alpha-numeric lowercase) (__REQUIRED__)
`source`           | where the files of the app can be downloaded (by default it will look for the branch `build`)
`terms`            | an object defining  properties for terms that need to be displayed/accepted by the user when installing the application ([more-info-below](#application-terms))
`time_interval`    | _(konnector specific)_ By defaults, konnector triggers are scheduled randomly between 00:00 AM and 05:00 AM. Those two values can be overwritten thanks to this property, by passing an array containing two values: first is the interval start hour, second is the interval end hour. Example: `[15, 21]` will randomly schedule the konnector trigger between 15:00 (03:00 PM) and 21:00 (09:00 PM). The time zone used is GMT.
`type`             | type of application (`konnector` or `webapp`) (__REQUIRED__)
`version`          | the current version number (__REQUIRED__)
`vendor_link`      | _(konnector specific)_ URL to editor or service website
`qualification_labels` | (konnector specific) Array of one or more labels from the [Cozy Client’s qualifications list](https://github.com/cozy/cozy-client/blob/master/packages/cozy-client/src/assets/qualifications.json) to associate with the files the konnector will receive from the website.
`features` | (konnector specific) Array of features added in the konnector from the list below.

#### Available manifest’s features list :

 - **2FA**

    Two Factors identification.

- **BILLS**

    Import bills documents, doctype “io.cozy.bills”.

 - **FILES**

    Import files documents, doctype “io.cozy.files”.

 - **CAPTCHA_RESOLUTION**

    The konnector using a captcha resolution process.

 - **CARBON_COPY**

    The konnector import legally true copy of the original files.

 - **DOC_QUALIFICATION**

    The konnector uses the first version of files qualifications, you may stumble upon on some konnectors wich hasn’t been treated.

 - **DOC_QUALIFICATION_V2**

    The konnector uses new version (last one for now) of files qualifications.

 - **ELECTRONIC_SAFE**

    Files comes from a known electronic safe.

 - **HEALTH**

    The konnector treat health documents

 - **HTML_TO_PDF**

    The konnector needs to convert HTML page(s) to make pdf files.

 - **IDENTITY**

    The konnector create identity(ies) for doctype “io.cozy.identities”

 - **LOGIN_OK**

    The konnector deactivate the auto-notification 

 - **METADATA_DEDUP**

    The konnector uses a fileIdAttribute as detection to avoid deduplication.

 - **VENDOR_REF**

    The konnector uses.

 - **SENTRY_V2**

    The konnector had been migrated (or packaged) to sentry V2 (errors.cozycloud.cc)

> __Notices:__
>
> - All images paths (`icon`, `partnership.icon` and `screenshots`) should be relative to the build directory. For example, here, the `icon.svg` is stored in the build root directory and all `screenshots` are store in a folder `screenshots` in the build directory. Therefore, if you use a bundler (like webpack) be sure to know exactly where the bundler will store these assets in the build directory (and change it in the manifest if needed).
> - All properties in `locales` objects will override the matched property of the main `manifest.webapp` body, if a property is not found in `locales` it will fallback to the main body one.
> - We use to have the `en` locale as default one if the one wanted by the user doesn't exist. Be sure to have, at least, that locale complete with the name and all descriptions.
> - In your build files, this `manifest.webapp` file must be at the root.

##### Translated manifest fields

Here are the properties that you can override using `locales` (we recommand to automatically build these properties according to your locales files if you're using a translating tool like `transifex`):

- `name`, the app's name
- `short_description`, short description of what the app do
- `long_description`, longer and more complete description of the app behaviour
- `changes`, description of your new version of the konnector or all changes since the last version
- `fields`, An object containing translations for fields.
- `screenshots`
- `folders`


```json
{
  "fields": {
    "email": {
      "type": "email"
    }
  },
  "locales": {
    "en": {
      "short_description": "Collect your Orange's bills",
      "fields": {
        "email": {
          "label": "Identifier (your email)"
        }
      }
    },
    "fr": {
      "short_description": "Récupère vos factures Orange",
      "fields": {
        "email": {
          "label": "Identifiant (votre adresse mail)"
        }
      }
    }
  }
}
```

##### Application terms

You can provide a related `terms` property if you want to display and make the user accept some terms (ToS for example) just before installing the application. Here are all properties allowed and used:

- `url`, the URL of the terms/contract to redirect the user to (__REQUIRED__)
- `version`: A specific version of the terms, we need it handle terms updates and ask the user again to accept the update. The special characters `[*+~.()'"!:@]` are not allowed here. (__REQUIRED__)
- `id`: An id for the terms. When accepting terms, we store in `io.cozy.terms`, a document containing the `id` and `version` so that we know which terms have been accepted, and show the user a modal if the terms have not been accepted yet. The special characters `[*+~.()'"!:@]` are not allowed here. (__REQUIRED__)

##### Konnectors folders handling

The `folders ` property is a list of objects with these following properties:

- `defaultDir`: (__REQUIRED__) The default root directory of your folder. In this folder will automatically be created a subfolder with the konnector name and into this latter a subfolder with the account name to store the related files. Here you can use some variables in the path like the following:
    - `$administrative`: Folder which will receive all administrative related files (bills, contracts, invoices...)
    - `$photos`: Folder which will receive all photos
    - `$konnector`: The name of the konnector

    > :warning: All paths provided using `defaultDir` will be the root directory, not the final folder which will receive the files. For example, if you set `$photos`, the final folder will be `$photos/$konnector/$account` in order to keep them always sorted by konnectors and accounts.

##### Konnectors fields property

The `fields` property is a JSON object describing the input fields needed to generate the konnector's configuration form. A typical example will be:

```JSON
{
  "fields": {
    "identifier": {
      "type": "text"
    },
    "secret": {
      "type": "password"
    }
  }
}
```

The keys of the `fields` object are the name/id of the fields. They will be passed as parameters to the konnector at every run.

Each fields may also have the following properties:

Property        | Description
----------------|---------------------------------------------------------------
identifier      | (Boolean) indicating if the field is the main identifier. By default, the `login` field is the identifier. Default value is false and there can be only one identifier
advanced        | Indicates if the field should be displayed in the "advanced" area of the form (default: `false`)
default         | Default value. It can a string for a text field, or an object for a select field (`"default": {"value": "foo","name": "bar"},`)
description     | Field description, as a locale key.
label           | Predefined label. This value must match a locale key provided by Cozy-Home. Example: With `label: "identifier"`, Cozy-Home will use the locale key `account.form.label.identifier`. Translations for these fields use the `locales` property in the manifest.
max             | Maximum length of the value (number of characters)
min             | Minimum length of the value (number of characters)
options         | When the field is a dropdown, list of available options
pattern         | Define a regex used to validate the field.
isRequired      | Boolean indicating if the field is required or not (default `true`)
type            | *Required*. Field type from `dropdown`, `email`, `hidden`, `password`, `text`, `checkbox`.


##### Konnectors message property

Messages are a common way to provide custom information to display in application. An app like cozy-home should have some specific area to display custom messages provided by the konnector.

Example:
```jsx
  // The final example will be available after the implementation of the whole mechanism,
  // but here is the global idea:
  {installSuccess &&
    <p>{t('home.konnector.install.success.message')}</p>
  }
  {installSuccess && konnector.manifest.messages.includes('success_message') &&
    <p>{t('konnector.manifest.locales.messages.success_message')}
  }
```

##### Categories and Data types

Categories are slugs from the following list:
* `energy`
* `insurance`
* `isp`
* `shopping`
* `telecom`
* `transport`
* `banking`
* `health`
* `host_provider`
* `online_services`
* `partners`
* `press`
* `productivity`
* `public_service`
* `social`

Data types are slugs from the following list:
* `activity`
* `appointment`
* `bankTransactions`
* `bankAccounts`
* `bill`
* `bloodPressure`
* `calendar`
* `certificate`
* `commit`
* `consumption`
* `contact`
* `contract`
* `courseMaterial`
* `document`
* `event`
* `family`
* `geopoint`
* `heartbeat`
* `home`
* `phonecommunicationlog`
* `podcast`
* `profile`
* `refund`
* `sinister`
* `sleepTime`
* `stepsNumber`
* `temperature`
* `travelDate`
* `tweet`
* `videostream`
* `weight`


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
editor         | Name of the editor matching the `{{EDITOR_TOKEN}}`

__:warning: Here the `slug` is the unique ID of the application in the registry, so it can't be changed after the application is already registered.__
</details>

### 3) Add a new version of a registered application

#### Via [`cozy-app-publish`][cozy-app-publish] (highly recommanded)

__Here we will show the classical way to add a version using the manual mode of [`cozy-app-publish`][cozy-app-publish] as reference. But you may need to look at  the [Automation CI part](#automation-ci) of this documentation instead.__

> __Prequisites__:
>
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

To add a new version for a registered application, you have to do a `POST` request with all needed information to the route `registryAddress/registry/:appSlug` to publish in default space or `registryAddress/:space/registry/:appSlug` for a named space (see [Spaces & Virtual Spaces](#spaces--virtual-spaces) below)
with `registryAddress` your registry address (for example here `http://localhost:8081`), `:appName` your application slug (here `drive`) and `:space` your registry space.

Let's add the version 1.0.1 of the Collect application for example:

```shell
# {{EDITOR_TOKEN}} -> your generated editor access token
curl -X "POST" "http://localhost:8081/registry/collect" \
     -H "Authorization: Token {{EDITOR_TOKEN}}" \
     -H "Content-Type: application/json" \
     -d $'{
  "url": "https://github.com/cozy/cozy-collect/archive/1.0.1.tar.gz",
  "sha256": "96212bf53ab618808da0a92c7b6d9f2867b1f9487ba7c1c29606826b107041b5",
  "version": "1.0.1",
}'
```

Field         | Description
--------------|-------------------------------------------------------------
url           | the archive source of your application, it will be downloaded and checked with the sha256 property
sha256        | the sha256 hash of your source archive matching the archive in `url` (see the notice below)
version       | version of the application, must match the one in the manifest (see the notice below)

> __:warning: Important notices:__
>
> - The version must match the one in the `manifest.webapp` file for stable release. For beta (X.X.X-betaX) or dev releases (X.X.X-dev.hash256), the version before the cyphen must match the one in the `manifest.webapp`.
> - For better integrity, the `sha256` provided must match the sha256 of the archive provided in `url`. If it's not the case, that will be considered as an error and the version won't be registered.

### Spaces & Virtual Spaces

#### Spaces

You can divide your applications between several isolated places, called
`spaces`.

When an application and its versions are published in a `space`, they are only
reachable in that one (you can consider a `space` like a entire sub-part of the
registry). It is espacially useful for splitting up applications by logical
topics.

Most of the CLI and API endpoints have a `space` option. You can refer to the
documentation or CLI help to view all available parameters.

##### Create a space

Spaces are defined in the config file and are automatically created during registry
launching.

Add a `space` entry, followed by your spaces names, and let the registry do the work:

```yaml
spaces: __default__ myspace foospace
```

##### Remove a space

To remove a space, you have to clean all the remaining apps & versions before removing the `space` entry name.

A CLI is available for the job:

```bash
$ cozy-apps-registry rm-space <your-space>
```

Example:

```bash
$ cozy-apps-registry rm-space foobar
Warning: You are going to remove space foobar and all its applications. This action is irreversible.
Please enter the space name to confirm: foobar
Removing app1/0.7.3-dev.f26bf2b8db3da459071a074a1367ce36e78bb34c
Removing app1/0.7.3-dev.cf1efba4c1b6dd08bb5857f5752790f0d2663d6d
Removing app1/0.7.3-dev.0bbd57a6ce50af82cfbefb8c231fbfe04516e742
Removing app1/0.7.3-dev.21338229a0c2317dc0f3b94e92b22a367f84c537
Removing app1/0.7.3-dev.08ab3624136fb70dc996003aebc3049af51f7438
Removing app1/0.7.3-dev.4e9d174a3b01acaf8a44b561455efc3f34871142
Removing app1/0.7.3-dev.b2654bf00be393aa611fcbb7f70a8ef671895a84
Removing app1/0.7.3-dev.860861868a5dfe294c7120d81fa9feb5387bb57f
Removing app2/0.1.9-dev.954dac9e12e080d591cb76591c311611fed1bea9
```

You can now delete the name from your config file.

#### Virtual Spaces

A `virtual space` is necessarily built over an existing `space`. It allows to
filter by selecting or rejecting applications available on the underlying space.

> :warning: Please note that it is not possible to publish applications or
> versions on a `virtual space`.

It is possible to change the name of an application in the virtual space,
without changing it in the underlying space, with the `cozy-apps-registry
overwrite-app-name` command. The same thing is possible for the icon with
`cozy-apps-registry overwrite-app-icon`. And the maintenance status can also
be changed in the virtual space with the `cozy-apps-registry maintenance`
commands. That's all for the moment.

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
>
> - A commit push to the branch master will publish your application in the `dev` channel of the registry.
> - A tag push (Github release) will publish a stable version (ex: `1.0.0`) or a beta version (ex: `1.0.1-beta2`) to the registry (automatically handled by the registry).
> - [`cozy-app-publish`][cozy-app-publish] will use the github archive URL computing to get the application tarball. If your applicaiton is not on Github, you may need to use the manual mode of the command.

## Access control and tokens

The read-only routes of the registry are all public and do not require any
access-control. However routes allowing to create applications and versions have
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

## Import/export

CouchDB & Swift can be exported into a single archive with `cozy-apps-registry export <dump.tar.gz>`.
Registry data are exported as below:

 * `registry/couchdb/{db}/{uuid}.json`: CouchDB document exported as JSON
 * `registry/swift/{file/path}`: Swift document, with the following tar custom metadata
    * `COZY.content-type`: associated content type

The generated archive can be imported with `cozy-apps-registry import -d <dump.tar.gz>`.
The `-d` option will drop CouchDB databases and Swift containers related to declared spaces on the registry configuration.

## Application confidence grade / labelling

The confidence grade of an applications can be specified by specifying the
`data_usage_commitment` and `data_usage_commitment_by` fields of the
application document.

Possible values for these properties are:

* `data_usage_commitment`: specify a technical commitment from the
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

## Universal links

The registry can manage [Universal links](https://developer.apple.com/ios/universal-links/).

### Configuration

#### Config file
Each space holds its own files. The space determination is based on the request host, so you must bind a domain to a space in the config file.

```yaml
domain_space:
  mycloud.com: "__default__"
  cloud.foobar.com: "foobar"
```

#### Files
Place your files (e.g `apple-app-site-association`) in the space container. The file must be prepended with `universallink/`

> For the `foobar` space and file `apple-app-site-association`, the file has to be named
`universallink/apple-app-site-association` and placed in the `foobar` container

### Usage
The following endpoint is available to get any file:
> `http://<yourdomain>/.well-known/:filename`

You can now query your endpoint to get your file:

```bash
curl -X GET http://cloud.foobar.com/.well-known/apple-app-site-association
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appID": "3AKXFMV43J.io.cozy.drive.mobile",
        "paths": ["/drive"]
      },
      {
        "appID": "3AKXFMV43J.io.cozy.banks.mobile",
        "paths": ["/banks"]
      },
      {
        "appID": "3AKXFMV43J.io.cozy.photos.mobile",
        "paths": ["/photos"]
      }
    ]
  }
}
```

## Budget-Insight web auth

For some banks integration (Paypal, Orange Bank, Revolut…), Budget-Insight need
something similar to universal link because they expect a static domain for
fallback but there is a specific domain per Cozy instance.
In contrast with universal links, query parameters (provided by BI) are propagated
to the final fallback redirection.

`http://<registry-domain>/biwebauth?fallback=http%3A%2F%2Fa.cozy%3Ffoo%3Dfoo&bar=bar`
redirect to `http://a.cozy?foo=foo&bar=bar`, merging fallback provided query
parameters (`foo=foo`) with webauth provided ones (`bar=bar`).

## Community

You can reach the Cozy Community by:

- Chatting with us on IRC [#cozycloud on Libera.Chat][libera]
- Posting on our [Forum][forum]
- Posting issues on the [Github repos][github]
- Say Hi! on [Twitter][twitter]


[cozy]: https://cozy.io "Cozy Cloud"
[cozy-app-publish]: https://github.com/cozy/cozy-app-publish
[libera]: https://web.libera.chat/#cozycloud
[forum]: https://forum.cozy.io/
[github]: https://github.com/cozy/
[twitter]: https://twitter.com/cozycloud
