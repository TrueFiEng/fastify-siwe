module.exports = {
  extends: [`${__dirname}/../../.eslintrc.json`],
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
}
