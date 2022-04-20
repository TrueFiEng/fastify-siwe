# @fastify/siwe

A SIWE plugin for fastify. Requires the @fastify/session and fastify-cookie plugins.

More about SIWE [here](https://login.xyz/).

# Steps

Add session model to your database models, here is prisma example:

```tsx
model Session {
  id          String
  // JSON-encoded session data
  data        Json

  @@id([id])
}
```

Then add request routes from module to your routing.

Next you should add @fastify/siwe plugin:

```tsx
const fastify = require('fastify')
const fastifySession = require('@fastify/siwe')

const app = fastify()
app.register(fastifySiwe, {
    secret?: 'a secret with minimum length of 32 characters, this value is required',
    storage?: DatabaseStorage,
    prismaClient?: PrismaClient
    })
```

#### Description:

`DatabaseStorage` - instance that implements FastifySessionPlugin.SessionStore

`PrismaClient` - selfdescriptive, this value is unnecessary when storage is provided

## Contributing

Contributions are always welcome, no matter how large or small. Before contributing, please read the [code of conduct](https://github.com/EthWorks/useDapp/blob/master/CODE_OF_CONDUCT.md) and [contribution policy](https://github.com/EthWorks/useDapp/blob/master/CONTRIBUTION.md).

### Before you issue pull request:

* Make sure linter passes.

To install dependencies type:

```sh
npm i -g pnpm
pnpm install
```

To build project:
```sh
pnpm build
```

To run linter type:
```sh
pnpm lint
```

## License

useDapp is released under the [MIT License](https://opensource.org/licenses/MIT).
