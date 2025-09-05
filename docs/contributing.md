---
title: Contributing to ArtisanPack UI Security
---

# Contributing to ArtisanPack UI Security

As an open source project, ArtisanPack UI Security is open to contributions from everyone. You don't need to be a developer to contribute. Whether it's contributing code, writing documentation, testing the package or anything in between there's a place for you here to contribute.

## Code of Conduct

In order to make this a best place for everyone to contribute, there are some hard and fast rules that everyone needs to abide by:

* ArtisanPack UI is open to everyone no matter your race, ethnicity, gender, who you love, etc. In order to keep it that way, there's zero tolerance for any racist, misogynistic, xenophobic, bigoted, Zionist, antisemitic (yes, there is a difference), Islamophobic, etc. messages. This includes messages sent to a fellow contributor outside of this repository. In short, don't be a jerk. Failure to comply will result in a ban from the project.
* Be respectful when communicating with fellow contributors.
* Respect the decisions made for what to include in the package.
* Work together to create the best possible security package.

## Ways to Contribute

There are many different ways to contribute to the ArtisanPack UI Security package:

* **Write code** - Improve the security functions or add new ones
* **Create tests** - Help ensure the package works correctly
* **Write documentation** - Improve guides, examples, and API docs
* **Report bugs** - Help identify issues in the package
* **Suggest features** - Propose new security functions or improvements
* **Security research** - Help identify and fix security vulnerabilities

## How to File a Bug Report

To file a bug report, please [add a new issue](https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security/-/issues/new).

Next, select the bug report template and fill it out as much as you can.

Please include:
- Your environment (operating system, PHP version, Laravel version, browser if applicable)
- Steps to reproduce the problem
- Expected behavior
- Actual behavior
- Code samples demonstrating the issue
- Screenshots or error messages if helpful

Please select the **Awaiting Review** milestone and add the necessary labels to the task.

Once you've filled out the issue, you can submit it and it will be reviewed by a maintainer as quickly as possible. Maintainers might ask you questions about the bug, so please be as responsive as possible to help resolve the issue quickly.

## How to File a Feature Request

To file a feature request, please [add a new issue](https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security/-/issues/new).

Next, select the feature request template and fill it out as much as you can.

Please describe:
- What you want the feature to be as much as possible
- Why it should be in the ArtisanPack UI Security package
- How it would improve security for users
- Any implementation ideas you might have

Please select the **Awaiting Review** milestone and add the necessary labels to the task.

Once you've filled out the issue, it will be reviewed by a maintainer. Maintainers might ask questions about the feature request to make a decision on whether to include it in the package.

**Note:** If your feature request is accepted, your original issue will be closed and transferred to a feature issue.

## Merge Requests

To file a merge request, first make sure that there isn't a merge request that already exists that covers what you're changing.

Next, add a new merge request and select the proper merge request template:

* **Bug** - For merge requests that fix a bug
* **Feature** - For merge requests that merge a new feature into the package
* **Task** - For merge requests that complete a task issue

The release template is only used for package releases and can only be added by maintainers.

### Before Submitting a Merge Request

1. **Run the tests** - Make sure all existing tests pass
2. **Add new tests** - Include tests for any new functionality
3. **Update documentation** - Update relevant docs for your changes
4. **Follow coding standards** - Use the naming conventions below
5. **Security check** - Ensure your changes don't introduce vulnerabilities

Fill out all sections of your selected merge request template and submit the request. Your request will need to be reviewed and approved by at least one maintainer.

## Development Setup

1. Clone the repository
2. Install dependencies: `composer install`
3. Run tests: `vendor/bin/pest` or `vendor/bin/phpunit`

## Testing

When contributing code, please include appropriate tests:

```php
// Example test for a new sanitization function
test('sanitize custom input', function () {
    expect(sanitizeCustom('input<script>'))
        ->toEqual('inputscript')
        ->and(sanitizeCustom('normal input'))
        ->toEqual('normal input');
});
```

## Naming Conventions

To keep things consistent across the codebase, please follow these naming conventions:

* **Class names** should be in Pascal Case (`ClassName`)
* **Function names and variables** should be in Camel Case (`functionName`/`variableName`)
* **Array keys** should be in Camel Case (`$array['arrayKey']`)
* **Table columns** should be in snake case (`table_column`)

## Security Contributions

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Email the maintainers privately with details
3. Allow time for the issue to be patched
4. Credit will be given for responsible disclosure

## Documentation Contributions

When updating documentation:

* Include YAML front matter with title
* Use clear, concise language
* Provide code examples where helpful
* Remove .md extensions from internal links (for GitLab wiki)
* Test all code examples to ensure they work

## Questions?

If you have questions about contributing, feel free to:

* Open a discussion issue
* Contact the maintainers
* Check out the main [Digital Shopfront CMS Wiki](https://gitlab.com/jacob-martella-web-design/digital-shopfront/digital-shopfront-core/digital-shopfront/-/wikis/home) for more information

Thank you for helping make ArtisanPack UI Security better!