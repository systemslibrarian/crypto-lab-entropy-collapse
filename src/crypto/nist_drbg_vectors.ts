// NIST CAVP HMAC_DRBG known-answer vectors, SHA-256, PredictionResistance=False.
// Source: NIST DRBGVS validation set (HMAC_DRBG.rsp), the four option groups that
// cross personalization-string {absent, present} with additional-input {absent,
// present}. Two COUNTs from each group are included (8 vectors total).
//
// DRBGVS call sequence for these groups:
//   instantiate(entropy, nonce, personalization)
//   reseed(reseedEntropy, reseedAdditional)
//   generate(returnedLen, additional[0])   -> discarded
//   generate(returnedLen, additional[1])   -> compared against `returned`

export interface DrbgKat {
  readonly group: string
  readonly count: number
  readonly entropy: string
  readonly nonce: string
  readonly personalization: string
  readonly reseedEntropy: string
  readonly reseedAdditional: string
  readonly additional: [string, string]
  readonly returned: string
}

export const NIST_HMAC_DRBG_SHA256: DrbgKat[] = [
  {
    group: 'pers=0, addl=0',
    count: 0,
    entropy: '06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d',
    nonce: '0e66f71edc43e42a45ad3c6fc6cdc4df',
    personalization: '',
    reseedEntropy: '01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552',
    reseedAdditional: '',
    additional: ['', ''],
    returned:
      '76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124',
  },
  {
    group: 'pers=0, addl=0',
    count: 1,
    entropy: 'aadcf337788bb8ac01976640726bc51635d417777fe6939eded9ccc8a378c76a',
    nonce: '9ccc9d80c89ac55a8cfe0f99942f5a4d',
    personalization: '',
    reseedEntropy: '03a57792547e0c98ea1776e4ba80c007346296a56a270a35fd9ea2845c7e81e2',
    reseedAdditional: '',
    additional: ['', ''],
    returned:
      '17d09f40a43771f4a2f0db327df637dea972bfff30c98ebc8842dc7a9e3d681c61902f71bffaf5093607fbfba9674a70d048e562ee88f027f630a78522ec6f706bb44ae130e05c8d7eac668bf6980d99b4c0242946452399cb032cc6f9fd96284709bd2fa565b9eb9f2004be6c9ea9ff9128c3f93b60dc30c5fc8587a10de68c',
  },
  {
    group: 'pers=0, addl=256',
    count: 0,
    entropy: '05ac9fc4c62a02e3f90840da5616218c6de5743d66b8e0fbf833759c5928b53d',
    nonce: '2b89a17904922ed8f017a63044848545',
    personalization: '',
    reseedEntropy: '2791126b8b52ee1fd9392a0a13e0083bed4186dc649b739607ac70ec8dcecf9b',
    reseedAdditional: '43bac13bae715092cf7eb280a2e10a962faf7233c41412f69bc74a35a584e54c',
    additional: [
      '3f2fed4b68d506ecefa21f3f5bb907beb0f17dbc30f6ffbba5e5861408c53a1e',
      '529030df50f410985fde068df82b935ec23d839cb4b269414c0ede6cffea5b68',
    ],
    returned:
      '02ddff5173da2fcffa10215b030d660d61179e61ecc22609b1151a75f1cbcbb4363c3a89299b4b63aca5e581e73c860491010aa35de3337cc6c09ebec8c91a6287586f3a74d9694b462d2720ea2e11bbd02af33adefb4a16e6b370fa0effd57d607547bdcfbb7831f54de7073ad2a7da987a0016a82fa958779a168674b56524',
  },
  {
    group: 'pers=0, addl=256',
    count: 1,
    entropy: '1bea3296f24e9242b96ed00648ac6255007c91f7c1a5088b2482c28c834942bf',
    nonce: '71073136a5cc1eb5b5fa09e1790a0bed',
    personalization: '',
    reseedEntropy: 'd714329f3fbea1df9d0b0b0d88dfe3774beb63d011935923d048e521b710dc6f',
    reseedAdditional: '4ef872fd211a426ea1085ab39eb220cc698fdfeabe49b8835d620ab7885de7a4',
    additional: [
      'd74d1669e89875852d9ccbf11c20fe3c13a621ebcb3f7edeea39a2b3379fdcf5',
      '0c8aa67ca310bd8e58c16aba35880f747266dbf624e88ec8f9ee9be5d08fdeb1',
    ],
    returned:
      'ce95b98f13adcdf7a32aa34709d6e02f658ae498d2ab01ce920f69e7e42c4be1d005acf0ca6b17891dfafc620dd4cd3894f8492a5c846089b9b452483eb0b91f3649ec0b6f98d1aaabc2e42cd39c2b25081b85ab50cb723007a0fd83550f32c210b7c4150b5a6bb3b0c9e3c971a09d43acb48e410a77f824b957092aa8ef98bc',
  },
  {
    group: 'pers=256, addl=0',
    count: 0,
    entropy: 'fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840',
    nonce: 'dd0820655cb2ffdb0da9e9310a67c9e5',
    personalization: 'f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c',
    reseedEntropy: 'e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6',
    reseedAdditional: '',
    additional: ['', ''],
    returned:
      'f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe',
  },
  {
    group: 'pers=256, addl=0',
    count: 1,
    entropy: 'cff72f345115376a57f4db8a5c9f64053e7379171a5a1e81e82aad3448d17d44',
    nonce: 'd1e971ec795d098b3dae14ffcbeecfd9',
    personalization: '6ec0c798c240f22740cad7e27b41f5e42dccaf66def3b7f341c4d827294f83c9',
    reseedEntropy: '45ec80f0c00cad0ff0b7616d2a930af3f5cf23cd61be7fbf7c65be0031e93e38',
    reseedAdditional: '',
    additional: ['', ''],
    returned:
      '17a7901e2550de088f472518d377cc4cc6979f4a64f4975c74344215e4807a1234eefef99f64cb8abc3fb86209f6fc7ddd03e94f83746c5abe5360cdde4f2525ccf7167e6f0befae05b38fd6089a2ab83719874ce8f670480d5f3ed9bf40538a15aaad112db1618a58b10687b68875f00f139a72bdf043f736e4a320c06efd2c',
  },
  {
    group: 'pers=256, addl=256',
    count: 0,
    entropy: 'cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416',
    nonce: 'd0c0d01d156016d0eb6b7e9c7c3c8da8',
    personalization: '6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa',
    reseedEntropy: '8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82',
    reseedAdditional: '1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3',
    additional: [
      '16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff',
      '53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2',
    ],
    returned:
      'dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f',
  },
  {
    group: 'pers=256, addl=256',
    count: 1,
    entropy: '3e42348bf76c0559cce9a44704308c85d9c205b676af0ac6ba377a5da12d3244',
    nonce: '9af783973c632a490f03dbb4b4852b1e',
    personalization: '2e51c7a8ac70adc37fc7e40d59a8e5bf8dfd8f7b027c77e6ec648bd0c41a78de',
    reseedEntropy: '45718ac567fd2660b91c8f5f1f8f186c58c6284b6968eadc9810b7beeca148a1',
    reseedAdditional: '63a107246a2070739aa4bed6746439d8c2ce678a54fc887c5aba29c502da7ba9',
    additional: [
      'e4576291b1cde51c5044fdc5375624cebf63333c58c7457ca7490da037a9556e',
      'b5a3fbd57784b15fd875e0b0c5e59ec5f089829fac51620aa998fff003534d6f',
    ],
    returned:
      'c624d26087ffb8f39836c067ba37217f1977c47172d5dcb7d40193a1cfe20158b774558cbee8eb6f9c62d629e1bcf70a1439e46c5709ba4c94a006ba94994796e10660d6cb1e150a243f7ba5d35c8572fd96f43c08490131797e86d3ed8467b692f92f668631b1d32862c3dc43bfba686fe72fdd947db2792463e920522eb4bc',
  },
]
