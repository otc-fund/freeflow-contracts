/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/user_escrow.json`.
 */
export type UserEscrow = {
  "address": "7PzcA2sNDzrvhTNLFScWZuNKS4g7jCCghsowZA9RsZ26",
  "metadata": {
    "name": "userEscrow",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "FreeFlow User Escrow Program"
  },
  "instructions": [
    {
      "name": "initializeRegistry",
      "discriminator": [
        189,
        181,
        20,
        17,
        174,
        57,
        249,
        59
      ],
      "accounts": [
        {
          "name": "foundation",
          "writable": true,
          "signer": true
        },
        {
          "name": "registry",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        },
        {
          "name": "initialSpender"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "initialSpender",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "updateSpenderRegistry",
      "discriminator": [
        157,
        82,
        4,
        110,
        188,
        138,
        26,
        58
      ],
      "accounts": [
        {
          "name": "foundation",
          "writable": true,
          "signer": true
        },
        {
          "name": "registry",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        }
      ],
      "args": [
        {
          "name": "addSpenders",
          "type": {
            "vec": "pubkey"
          }
        },
        {
          "name": "removeSpenders",
          "type": {
            "vec": "pubkey"
          }
        }
      ]
    },
    {
      "name": "purchaseAndEscrow",
      "discriminator": [
        6,
        107,
        2,
        142,
        224,
        10,
        175,
        116
      ],
      "accounts": [
        {
          "name": "user",
          "writable": true,
          "signer": true
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "userEscrowToken",
          "writable": true
        },
        {
          "name": "treasuryVaultToken",
          "writable": true
        },
        {
          "name": "treasuryAuthority",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  116,
                  114,
                  101,
                  97,
                  115,
                  117,
                  114,
                  121,
                  95,
                  97,
                  117,
                  116,
                  104,
                  111,
                  114,
                  105,
                  116,
                  121
                ]
              }
            ]
          }
        },
        {
          "name": "tokenMint"
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "paymentAmount",
          "type": "u64"
        },
        {
          "name": "paymentType",
          "type": {
            "defined": {
              "name": "paymentType"
            }
          }
        }
      ]
    },
    {
      "name": "purchaseAndEscrowPhase2",
      "discriminator": [
        11,
        159,
        203,
        84,
        97,
        190,
        183,
        229
      ],
      "accounts": [
        {
          "name": "user",
          "writable": true,
          "signer": true
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "userToken",
          "writable": true
        },
        {
          "name": "userEscrowToken",
          "writable": true
        },
        {
          "name": "tokenMint"
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "minFlowAmount",
          "type": "u64"
        },
        {
          "name": "flowAmount",
          "type": "u64"
        }
      ]
    },
    {
      "name": "spendFromEscrow",
      "discriminator": [
        43,
        187,
        150,
        230,
        49,
        39,
        185,
        239
      ],
      "accounts": [
        {
          "name": "serviceAuthority",
          "signer": true
        },
        {
          "name": "user"
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "userEscrowToken",
          "writable": true
        },
        {
          "name": "relayToken"
        },
        {
          "name": "relay"
        },
        {
          "name": "spenderRegistry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        },
        {
          "name": "tokenMint",
          "writable": true
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "relay",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "holdClientFunds",
      "discriminator": [
        68,
        218,
        92,
        86,
        161,
        63,
        178,
        103
      ],
      "accounts": [
        {
          "name": "serviceAuthority",
          "signer": true
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "user"
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "fundHold",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  102,
                  117,
                  110,
                  100,
                  95,
                  104,
                  111,
                  108,
                  100
                ]
              },
              {
                "kind": "account",
                "path": "user"
              },
              {
                "kind": "arg",
                "path": "claimHash"
              }
            ]
          }
        },
        {
          "name": "spenderRegistry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "claimHash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        },
        {
          "name": "sessionId",
          "type": {
            "array": [
              "u8",
              16
            ]
          }
        }
      ]
    },
    {
      "name": "releaseFunds",
      "discriminator": [
        225,
        88,
        91,
        108,
        126,
        52,
        2,
        26
      ],
      "accounts": [
        {
          "name": "serviceAuthority",
          "signer": true
        },
        {
          "name": "user"
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "fundHold",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  102,
                  117,
                  110,
                  100,
                  95,
                  104,
                  111,
                  108,
                  100
                ]
              },
              {
                "kind": "account",
                "path": "user"
              },
              {
                "kind": "arg",
                "path": "claimHash"
              }
            ]
          }
        },
        {
          "name": "spenderRegistry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        }
      ],
      "args": [
        {
          "name": "claimHash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "burnHeldFunds",
      "discriminator": [
        249,
        189,
        183,
        158,
        102,
        178,
        156,
        176
      ],
      "accounts": [
        {
          "name": "serviceAuthority",
          "signer": true
        },
        {
          "name": "user"
        },
        {
          "name": "userEscrow",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  95,
                  101,
                  115,
                  99,
                  114,
                  111,
                  119
                ]
              },
              {
                "kind": "account",
                "path": "user"
              }
            ]
          }
        },
        {
          "name": "userEscrowToken",
          "writable": true
        },
        {
          "name": "fundHold",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  102,
                  117,
                  110,
                  100,
                  95,
                  104,
                  111,
                  108,
                  100
                ]
              },
              {
                "kind": "account",
                "path": "user"
              },
              {
                "kind": "arg",
                "path": "claimHash"
              }
            ]
          }
        },
        {
          "name": "spenderRegistry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  112,
                  101,
                  110,
                  100,
                  101,
                  114,
                  95,
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ]
          }
        },
        {
          "name": "tokenMint",
          "writable": true
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        }
      ],
      "args": [
        {
          "name": "claimHash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "userEscrow",
      "discriminator": [
        242,
        233,
        85,
        38,
        26,
        5,
        142,
        109
      ]
    },
    {
      "name": "fundHold",
      "discriminator": [
        197,
        82,
        233,
        139,
        233,
        49,
        149,
        164
      ]
    },
    {
      "name": "authorizedSpenderRegistry",
      "discriminator": [
        57,
        77,
        119,
        38,
        68,
        183,
        232,
        130
      ]
    }
  ],
  "events": [
    {
      "name": "purchaseAndEscrowed",
      "discriminator": [
        4,
        193,
        238,
        35,
        140,
        94,
        55,
        141
      ]
    },
    {
      "name": "spentFromEscrow",
      "discriminator": [
        183,
        212,
        167,
        66,
        141,
        157,
        2,
        37
      ]
    },
    {
      "name": "spenderRegistryUpdated",
      "discriminator": [
        199,
        246,
        190,
        59,
        255,
        88,
        241,
        200
      ]
    },
    {
      "name": "fundsHeld",
      "discriminator": [
        150,
        85,
        193,
        137,
        175,
        80,
        147,
        7
      ]
    },
    {
      "name": "fundsReleased",
      "discriminator": [
        178,
        119,
        252,
        230,
        131,
        104,
        210,
        210
      ]
    },
    {
      "name": "fundsBurned",
      "discriminator": [
        135,
        68,
        24,
        12,
        215,
        232,
        170,
        26
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "insufficientBalance",
      "msg": "Insufficient escrow balance"
    },
    {
      "code": 6001,
      "name": "unauthorizedCaller",
      "msg": "Caller is not in the verified spender registry"
    },
    {
      "code": 6002,
      "name": "invalidPaymentAmount",
      "msg": "Invalid payment amount"
    },
    {
      "code": 6003,
      "name": "invalidRelayWallet",
      "msg": "Relay wallet does not match expected destination"
    },
    {
      "code": 6004,
      "name": "notFoundation",
      "msg": "Only foundation multisig can update spender registry"
    },
    {
      "code": 6005,
      "name": "holdNotActive",
      "msg": "Hold is not in Active state"
    },
    {
      "code": 6006,
      "name": "insufficientEffectiveBalance",
      "msg": "Insufficient effective balance (balance - held < amount)"
    }
  ],
  "types": [
    {
      "name": "userEscrow",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "balance",
            "type": "u64"
          },
          {
            "name": "sessionId",
            "type": {
              "option": {
                "array": [
                  "u8",
                  16
                ]
              }
            }
          },
          {
            "name": "lastTopupTs",
            "type": "u64"
          },
          {
            "name": "held",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "fundHold",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "claimHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "sessionId",
            "type": {
              "array": [
                "u8",
                16
              ]
            }
          },
          {
            "name": "createdAt",
            "type": "i64"
          },
          {
            "name": "status",
            "type": {
              "defined": {
                "name": "holdStatus"
              }
            }
          }
        ]
      }
    },
    {
      "name": "authorizedSpenderRegistry",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "type": "pubkey"
          },
          {
            "name": "activeSpenders",
            "type": {
              "vec": "pubkey"
            }
          },
          {
            "name": "version",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "paymentType",
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "sol"
          },
          {
            "name": "usdc"
          },
          {
            "name": "usdt"
          },
          {
            "name": "creditCard"
          },
          {
            "name": "dex"
          }
        ]
      }
    },
    {
      "name": "holdStatus",
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "active"
          },
          {
            "name": "released"
          },
          {
            "name": "burned"
          }
        ]
      }
    },
    {
      "name": "purchaseAndEscrowed",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "paymentType",
            "type": {
              "defined": {
                "name": "paymentType"
              }
            }
          },
          {
            "name": "paymentAmount",
            "type": "u64"
          },
          {
            "name": "flowAmount",
            "type": "u64"
          },
          {
            "name": "escrowBalance",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "spentFromEscrow",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "relay",
            "type": "pubkey"
          },
          {
            "name": "remainingBalance",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "spenderRegistryUpdated",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "addSpenders",
            "type": {
              "vec": "pubkey"
            }
          },
          {
            "name": "removeSpenders",
            "type": {
              "vec": "pubkey"
            }
          },
          {
            "name": "version",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "fundsHeld",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "claimHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "sessionId",
            "type": {
              "array": [
                "u8",
                16
              ]
            }
          },
          {
            "name": "totalHeld",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "fundsReleased",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "claimHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "totalHeld",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "fundsBurned",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "user",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "claimHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "remainingBalance",
            "type": "u64"
          }
        ]
      }
    }
  ]
};
