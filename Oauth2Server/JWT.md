References for Lobucci/jwt

- https://github.com/lcobucci/jwt/issues/93

We have the Signer interface:

```php
interface Signer
{
    public function algorithmId(): string;
    public function sign(string $payload, Key $key): string;
    public function verify(string $expected, string $payload, Key $key): bool;
}
```

We have the Key interface:

```php
interface Key
{
    public function contents(): string;
    public function passphrase(): string;
}
```

We have the InMemory implementation of Key as a provided way to send a key into the signing mechanism of your choice.

What exactly is missing that could be considered general-purpose (as to warrant implementing this here instead of a separate add-on library) that you would need for any cloud operation?

Have you considered implementing a bit of glue code to utilize the sign() method of the AWS client library [https://github.com/aws/aws-sdk-php/blob/master/src/Kms/KmsClient.php#L95]?
