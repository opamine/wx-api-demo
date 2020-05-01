const express = require("express");
const axios = require("axios");
const { createHash } = require("crypto");
const app = express();

/**
 * @param {string} algorithm
 * @param {any} content
 *  @return {string}
 */
const encrypt = (algorithm, content) => {
  let hash = createHash(algorithm);
  hash.update(content);
  return hash.digest("hex");
};

/**
 * @param {any} content
 *  @return {string}
 */
const sha1 = (content) => encrypt("sha1", content);

const grant_type = "client_credential";
// ↓↓↓↓↓↓↓↓ 需要返回前端 ↓↓↓↓↓↓↓↓
const appId = "wxde78c242b8e5a88e";
// ↑↑↑↑↑↑↑↑ 需要返回前端 ↑↑↑↑↑↑↑↑
const secret = "9797085a40ea0243f2d9a4523e009b96";

let access_token = "";

let jsapi_ticket = "";
let expires_time = null;

// ↓↓↓↓↓↓↓↓ 需要返回前端 ↓↓↓↓↓↓↓↓
let noncestr = ""; // 随机串，可以自己生成，也可以从前端拿(来源无要求)
let timestamp = null; // 时间戳，服务端自己生成
let signature = ""; // 签名，前端调API的核心字段
// ↑↑↑↑↑↑↑↑ 需要返回前端 ↑↑↑↑↑↑↑↑

// let url = ""; // 必须前端发过来

function getAccessToken() {
  return axios.get("https://api.weixin.qq.com/cgi-bin/token", {
    params: { grant_type, appId, secret },
  });
}

function getJsAPITicket(access_token) {
  return axios.get("https://api.weixin.qq.com/cgi-bin/ticket/getticket", {
    params: {
      access_token,
      type: "jsapi",
    },
  });
}

async function setBaseValue() {
  try {
    const { data: res1 } = await getAccessToken();
    // 从拿到 access_token 开始计算有效期
    timestamp = createTimestamp();
    access_token = res1.access_token;
    const { data: res2 } = await getJsAPITicket(access_token);
    jsapi_ticket = res2.ticket;
    expires_time = timestamp - 0 + res2.expires_in;
  } catch (err) {
    console.log(err);
  }
}

function createNonceStr() {
  return Math.random().toString(36).substr(2, 15);
}

function createTimestamp() {
  return parseInt(new Date().getTime() / 1000) + '';
}

// 设置跨域和响应数据格式 // Access-Control-Allow-Credentials
app.all("/*", (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "PUT,POST,GET,DELETE,OPTIONS");
  if (req.method == "OPTIONS") res.sendStatus(200);
  /*让options请求快速返回*/ else next();
});

// 前端发来请求，需要 签名 调取 WX-JS-API, 在此处理
app.get("/wx-api-info", async (req, res) => {
  if (createTimestamp() >= expires_time) {
    // 依次获取 access_token 和 jsapi_ticket
    await setBaseValue();
  }
  let { url, acode } = req.query;
  // 如果前端未传 url, 响应 400, 结束执行
  if (!url) {
    return res.status(400).send({
      code: 0,
      data: null,
      msg: "缺少必要参数",
    });
  }
  noncestr = acode;
  // 如果前端未传随机码，自己生成
  if (!acode) {
    noncestr = createNonceStr();
  }

  // 开始生成签名 signature
  // 步骤1. 对所有待签名参数按照字段名的 ASCII 码从小到大排序（字典序）后，使用URL键值对的格式（即key1=value1&key2=value2…）拼接成字符串string1：
  string1 =
    "jsapi_ticket=" +
    jsapi_ticket +
    "&noncestr=" +
    noncestr +
    "&timestamp=" +
    timestamp +
    "&url=" +
    url;
  console.log(string1);

  // 步骤2. 对 string1 进行sha1 签名，得到 signature ：
  signature = sha1(string1);
  console.log('signature为：' + signature);
  res.status(200).send({
    code: 1,
    data: { appId, nonceStr: noncestr, timestamp, signature },
    msg: '获取签名成功！'
  });
});

app.listen(3004, () => {
  console.log("server runing, listen port 3004!");
});
