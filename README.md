# Digital Shopfront CMS Security

This is the repository for the Digital Shopfront CMS Security package. You can learn more about [Digital Shopfront CMS here](https://gitlab.com/jacob-martella-web-design/digital-shopfront/digital-shopfront-core/digital-shopfront).

The package adds in security functions for the CMS, including sanitation and escaping functions.

## Installation

You can install the security package by running the following composer command.

`composer require digitalshopfront/security`

## Usage

You can use any of the security functions like this:

```
use Digitalshopfront\Security\Facades\Security as Security;

echo Security::escHtml('#38ed24');
```

You can also call any of the functions directly like this:

`echo escHtml('#38ed24');`

## Contributing

As an open source project, this package is open to contributions from anyone. Please [read through the contributing
guidelines](CONTRIBUTING.md) to learn more about how you can contribute to this project.
