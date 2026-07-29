import { YamlSecurity } from '../src/index.js';

const parser = new YamlSecurity();

// Parse simple YAML
const config = parser.parse(`
server:
  host: localhost
  port: 8080
  features:
    - ssl
    - cors
`);

if (config.ok) {
  console.log('Config:', JSON.stringify(config.result, null, 2));
} else {
  console.error('Error:', config.error);
}
