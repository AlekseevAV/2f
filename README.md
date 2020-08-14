# Two-factor authentication agent

Currently support only macOS.

This package use build-in macOS security util to manage secrets in keychain storage. 


## Install

Homebrew:

    brew tap alekseevav/tap
    brew install f2f

Brew formula named `f2f` because of ruby name convention.

From sources:

    go get github.com/AlekseevAV/2f

## Usage

New keychain storage will be created on first run:

    go run main.go -add gmail
    password for new keychain: xxxxxxx
    2f key for gmail: afafasdfdsfa

After that you can find new keychain in "Keychain Access.app" and get full access with your password.

You can specify keychain name by setting `KEYCHAIN_NAME` environment variable.

All available commands:

    2f -add [-7] [-8] name
    2f -delete name
    2f -list
    2f -help
    2f name

## Example

Add key:

    $ 2f -add gmail
    2f key for gmail: asdfasfrwerwr

Get two-factor key:

    $ 2f gmail
    516214

Delete key:

    $ 2f -delete gmail

By default all keys created with 6 digits code, but you can set 7 or 8 digits by:

    $ 2f -add -7 gmail
    2f key for gmail: asdfasfrwerwr
    $ 2f gmail
    1524561
    
    $ 2f -add -8 gmail
    2f key for gmail: asdfasfrwerwr
    $ 2f gmail
    51635261


## Other

Inspired by this project - [https://github.com/rsc/2fa](https://github.com/rsc/2fa).

But storing keys in files with base32 encoding just not enough secure for me.
