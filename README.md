# ucenter

Oauth2 用户中心

## 用户模型

| 字段     | 类型|长度     | 备注                       |
| -------- | ---|----- | -------------------------- |
| Username |string |1-20  | 英文数字混合               |
| Password | string|6-32  |                            |
| Bio      | string|1-255 |  |
|Avatar |bool|1|是否已上传头像|

## 客户端模型

| 字段     | 类型   | 长度 | 备注             |
| -------- | ------ | ---- | ---------------- |
| ClientID | string |      | uid-randomstring |

