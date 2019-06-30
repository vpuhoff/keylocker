# Heading 1 Keylocker CLI
Library with the CLI to save the encrypted secrets in the configuration file, but a transparent read and write the new settings in the app.

## Heading 2 Simple usage in CLI:
> Blockquote keylocker generate-key
> Blockquote keylocker list
> Blockquote keylocker read <keyname>
> Blockquote keylocker remove <keyname>
> Blockquote keylocker write <keyname> <value>

## Heading 2 Simple usage in code:
> Blockquote from keylocker import Storage
> Blockquote secrets = Storage()
> Blockquote print(secrets['test'])