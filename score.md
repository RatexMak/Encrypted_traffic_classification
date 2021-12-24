

# overview

test with 0511.pcap

| SSH          | svc_clf | svc_rbf | tree_clf | rnd_clf |
| ------------ | ------- | ------- | -------- | ------- |
| precision    | 0.273   | 0.250   | 0.211    | 0.222   |
| recall       | 0.088   | 0.206   | 0.118    | 0.059   |
| accuracy     | 0.936   | 0.921   | 0.926    | 0.936   |
| F-Measure    | 0.133   | 0.226   | 0.151    | 0.093   |
| completeness | 0.324   | 0.824   | 0.559    | 0.265   |
| unrecognized | 0.000   | 0.000   | 0.000    | 0.000   |

***

| TLS          | svc_clf | svc_rbf | tree_clf | rnd_clf |
| ------------ | ------- | ------- | -------- | ------- |
| precision    | 0.168   | 0.648   | 0.737    | 0.737   |
| recall       | 0.856   | 0.613   | 0.658    | 0.631   |
| accuracy     | 0.203   | 0.869   | 0.895    | 0.892   |
| F_Measure    | 0.281   | 0.630   | 0.695    | 0.680   |
| completeness | 5.090   | 0.946   | 0.892    | 0.856   |
| unrecognized | 0.000   | 0.000   | 0.000    | 0.000   |

# score_type: SSH

## svc_clf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.273 |
|    recall    | 0.088 |
|   accuracy   | 0.936 |
|  F_Measure   | 0.133 |
| completeness | 0.324 |
| unrecognized | 0.000 |

## svc_rbf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.250 |
|    recall    | 0.296 |
|   accuracy   | 0.921 |
|  F_Measure   | 0.226 |
| completeness | 0.824 |
| unrecognized | 0.000 |

## tree_clf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.211 |
|    recall    | 0.118 |
|   accuracy   | 0.926 |
|  F_Measure   | 0.151 |
| completeness | 0.559 |
| unrecognized | 0.000 |

## rnd_clf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.222 |
|    recall    | 0.059 |
|   accuracy   | 0.936 |
|  F_Measure   | 0.093 |
| completeness | 0.265 |
| unrecognized | 0.000 |

# score_type: TLS

## svc_clf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.168 |
|    recall    | 0.856 |
|   accuracy   | 0.203 |
|  F_Measure   | 0.281 |
| completeness | 5.090 |
| unrecognized | 0.000 |

## svc_rbf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.648 |
|    recall    | 0.613 |
|   accuracy   | 0.869 |
|  F_Measure   | 0.630 |
| completeness | 0.946 |
| unrecognized | 0.000 |

## tree_clf:

| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.737 |
|    recall    | 0.658 |
|   accuracy   | 0.895 |
|  F_Measure   | 0.695 |
| completeness | 0.892 |
| unrecognized | 0.000 |

## rnd_clf:
| Measurement  | score |
| :----------: | :---: |
|  precision   | 0.737 |
|    recall    | 0.631 |
|   accuracy   | 0.892 |
|  F-Measure   | 0.680 |
| completeness | 0.856 |
| unrecognized | 0.000 |
