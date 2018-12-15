# lib-mealie-crypt
Typescript-based mealie-crypt library. A mealie-crypt file is an encrypted key-value store.
Key-value pairs are organised into groups, with all keys and values in a group being AES-256-CBC encrypted with the
same 256 bit group key, and a distinct 128 bit salt (iv). The group-key itself, is encrypted by using the `rsa-ssh` keys of each user that is part
of the group.


