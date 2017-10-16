How to contribute to the Cozy Regsitry v3?
==========================================

Thank you for your interest in contributing to Cozy! There are many ways to
contribute, and we appreciate all of them.


Security Issues
---------------

If you discover a security issue, please bring it to their attention right
away! Please **DO NOT** file a public issue, instead send your report
privately to security AT cozycloud DOT cc.

Security reports are greatly appreciated and we will publicly thank you for
it. We currently do not offer a paid security bounty program, but are not
ruling it out in the future.


Bug Reports
-----------

While bugs are unfortunate, they're a reality in software. We can't fix what
we don't know about, so please report liberally. If you're not sure if
something is a bug or not, feel free to file a bug anyway.

Opening an issue is as easy as following [this
link](https://github.com/cozy/cozy-apps-registry/issues/new) and filling out the
fields. Here are some things you can write about your bug:

- A short summary
- What did you try, step by step?
- What did you expect?
- What did happen instead?
- What is the version of the Cozy Stack?


Pull Requests
-------------

### Workflow

Pull requests are the primary mechanism we use to change Cozy. GitHub itself
has some [great documentation
](https://help.github.com/categories/collaborating-with-issues-and-pull-requests/)
on using the Pull Request feature. We use the 'fork and pull' model described
there.

#### Step 1: Fork

Fork the project on GitHub and [check out your copy
locally](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html).

```
$ go get -u github.com/cozy/cozy-apps-registry.git
$ cd $GOPATH/src/github.com/cozy/cozy-apps-registry
$ git remote add fork git://github.com/username/cozy-apps-registry.git
```

#### Step 2: Branch

Create a branch and start hacking:

```
$ git checkout -b my-branch -t origin/master
```

#### Step 3: Code

Well, I think you know how to do that. Just be sure to follow the coding
guidelines from the Go community (gofmt, [Effective
Go](https://golang.org/doc/effective_go.html), comment the code, etc.).

#### Step 4: Test

Don't forget to add tests and be sure they are green:

```
$ go test -v
```

#### Step 5: Commit

Writing [good commit
messages](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
is important. A commit message should describe what changed and why.

#### Step 6: Rebase

Use `git rebase` (not `git merge`) to sync your work from time to time.

```
$ git fetch origin
$ git rebase origin/master
```

#### Step 7: Push

```
$ git push fork my-branch
```

Go to https://github.com/username/cozy-apps-registry and select your branch. Click the
'Pull Request' button and fill out the form.

Pull requests are usually reviewed within a few days. If there are comments to
address, apply your changes in a separate commit and push that to your branch.
Post a comment in the pull request afterwards; GitHub does not send out
notifications when you add commits.


Community
---------

You can help us by making our community even more vibrant. For example, you
can write a blog post, take some videos, answer the questions on [the
forum](https://forum.cozycloud.cc), organize new meetups, and speak about what
you like in Cozy!
