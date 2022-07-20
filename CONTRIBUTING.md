# Contributing

We welcome contributions in several forms, e.g.

* Coding
* Documenting
* Testing / Bug reports
* Sponsoring
* etc.

You may have a look at [14 Ways to Contribute to Open Source without Being
a Programming Genius or a Rock Star]
(https://smartbear.com/blog/test-and-monitor/14-ways-to-contribute-to-open-source-without-being/).

When planning for major code contributions to this repository,
please first discuss the changes you wish to make via issue, email,
or any other method with the owners of this repository beforehand.

Please note that we have a [code of conduct](CODE_OF_CONDUCT.md);
please follow it in all your interactions with the project.

## Developer Certificate of Origin

All commits must be signed-off by their author when contributing.

When signing-off a patch for this project like this

    Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (no pseudonyms or anonymous contributions),
you declare the following:

    By making a contribution to this project, I certify that:

        (a) The contribution was created in whole or in part by me and
            I have the right to submit it under the open source license
            indicated in the file; or

        (b) The contribution is based upon previous work that, to the best
            of my knowledge, is covered under an appropriate open source
            license and I have the right under that license to submit that
            work with modifications, whether created in whole or in part
            by me, under the same open source license (unless I am
            permitted to submit under a different license), as indicated
            in the file; or

        (c) The contribution was provided directly to me by some other
            person who certified (a), (b) or (c) and I have not modified it.

        (d) I understand and agree that this project and the contribution
            are public and that a record of the contribution (including all
            personal information I submit with it, including my sign-off) is
            maintained indefinitely and may be redistributed consistent with
            this project or the open source license(s) involved.

## Workflow

Please use the [Forking Workflow]
(https://www.atlassian.com/git/tutorials/comparing-workflows/forking-workflow)
and send us Pull Requests.

You may merge a Pull Request in
once you have the sign-off of two other developers,
or if you do not have permission to do that,
you may request the second reviewer to merge it for you.

### Commit Message

Commit messages shall follow the conventions defined by
[conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

> **HINT**: A good way to create commit messages is by using the tool `git gui`.
>
> **NOTE**: Changes supposed to be upstreamed shall structure the commit message
> according to the upstream project's guidelines.

### What to use as scope

In most cases the changed component is a good choice as scope,
e.g., if the change is done in the documentation, the scope should be *doc*.

For documentation changes the section that was changed makes a good scope name,
e.g., use *FAQ* if you changed that section.
