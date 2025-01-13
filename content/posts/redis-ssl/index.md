

+++

date = '2025-01-13T10:00:00+08:00'
draft = false
title = 'Redis 开启 SSL'

+++





[TOC]



# Redis 开启 SSL

> 在 Redis 6.0 版本之后，官方开始支持SSL/TLS。



## Redis 服务如何开启 SSL



### 修改如下配置

| 属性             | 值               | 注                                                           |
| ---------------- | ---------------- | ------------------------------------------------------------ |
| port             | 0                | 禁用未加密的普通 Redis 端口                                  |
| tls-port         | 6379             | 指定 Redis TLS 端口                                          |
| tls-cert-file    | /certs/redis.crt | 服务器证书                                                   |
| tls-key-file     | /certs/redis.key | 服务器私钥                                                   |
| tls-ca-cert-file | /certs/ca.crt    | CA 根证书                                                    |
| tls-auth-clients | optional         | yes：客户端必须使用受信任的证书<br />optional：客户端可以使用受信任的证书或者不使用证书 |



## 适配方案

### 配置中心-Redis

#### standalone

##### 未开启 ssl

```java
{
    "codecEnabled":true,
    "key":"<random>",
    "type":"standalone",
    "password":"<密文>",
    "standalone":{
        "host":"127.0.0.1",
        "port":6379,
        "ssl":false
    }
}
```



##### 开启 ssl

```json
{
    "codecEnabled": true,
    "key": "<random>",
    "type": "standalone",
    "password": "<密文>",
    "standalone": {
        "host": "127.0.0.1",
        "port": 6379
    },
    "ssl": true,
    "caCertFile": "/certs/ca.crt",
    "clientCertFile": "/certs/redis-client.crt",
    "clientKeyFile": "/certs/redis-client.key"
}
```



#### cluster

##### 未开启 ssl

```json
{
    "codecEnabled": true,
    "key": "<random>",
    "type": "cluster",
    "password": "<密文>",
    "cluster": [
        {
            "host": "192.168.0.1",
            "port": 6379,
            "ssl": false
        },
        {
            "host": "192.168.0.2",
            "port": 6379,
            "ssl": false
        },
        {
            "host": "192.168.0.3",
            "port": 6379,
            "ssl": false
        },
        {
            "host": "192.168.0.4",
            "port": 6379,
            "ssl": false
        },
        {
            "host": "192.168.0.5",
            "port": 6379,
            "ssl": false
        },
        {
            "host": "192.168.0.6",
            "port": 6379,
            "ssl": false
        }
    ]
}
```



##### 开启 ssl

```json
{
    "codecEnabled": true,
    "key": "<random>",
    "type": "cluster",
    "password": "<密文>",
    "cluster": [
        {
            "host": "192.168.0.1",
            "port": 6379
        },
        {
            "host": "192.168.0.2",
            "port": 6379
        },
        {
            "host": "192.168.0.3",
            "port": 6379
        },
        {
            "host": "192.168.0.4",
            "port": 6379
        },
        {
            "host": "192.168.0.5",
            "port": 6379
        },
        {
            "host": "192.168.0.6",
            "port": 6379
        }
    ],
    "ssl": true,
    "caCertFile": "/certs/ca.crt",
    "clientCertFile": "/certs/redis-client.crt",
    "clientKeyFile": "/certs/redis-client.key"
}
```



### java-ssl

#### 方案一：不配置证书（仅使用安全协议）

> tls-auth-clients optional

##### Lettuce

```java
	public static void main(String[] args) throws Exception {

		SslOptions sslOptions = SslOptions.builder().jdkSslProvider().build();

		ClientOptions clientOptions = ClientOptions.builder().sslOptions(sslOptions).build();

		LettuceClientConfiguration lettuceClientConfiguration = LettuceClientConfiguration.builder().useSsl().disablePeerVerification().and().clientOptions(clientOptions).build();

		RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration();
		configuration.setHostName("192.168.81.98");
		configuration.setPort(6379);
		configuration.setPassword("123456");

		LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory(configuration, lettuceClientConfiguration);

		lettuceConnectionFactory.afterPropertiesSet();

		RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(lettuceConnectionFactory);
		redisTemplate.setDefaultSerializer(RedisSerializer.string());
		redisTemplate.afterPropertiesSet();

		redisTemplate.opsForValue().set("b", "22");

		System.out.println(redisTemplate.opsForValue().get("b"));

	}
```

##### Redisson

```java
	public static void main(String[] args) throws Exception {
		// redisson配置文件
		Config config = new Config();
		config.setCodec(new JsonJacksonCodec());

		// 单机模式
		SingleServerConfig ssc = config.useSingleServer();

		// No SSL certificate verification
		ssc.setSslVerificationMode(SslVerificationMode.NONE);

		// 地址
		ssc.setAddress("rediss://192.168.81.98:6379");
		// 密码
		ssc.setPassword("123456");

		RedissonClient redissonClient = Redisson.create(config);

		// 获取 RBucket 对象
		RBucket<String> bucket = redissonClient.getBucket("aa");

		// 设置 Key-Value
		bucket.set("22");

		System.out.println(bucket.get());

	}
```



#### 方案二：配置证书（双向认证）

> tls-auth-clients optional/yes



##### Lettuce

```java
	public static void main(String[] args) throws Exception {

		SslOptions sslOptions = SslOptions.builder().jdkSslProvider().sslContext(sslContextBuilder -> {
			sslContextBuilder.trustManager(new File("C:\\Java\\myredis\\certs\\ca.crt"));
			sslContextBuilder.keyManager(new File("C:\\Java\\myredis\\certs\\redis-client.crt"), new File("C:\\Java\\myredis\\certs\\redis-client.key"));
		}).build();

		ClientOptions clientOptions = ClientOptions.builder().sslOptions(sslOptions).build();

		LettuceClientConfiguration lettuceClientConfiguration = LettuceClientConfiguration.builder().useSsl().and().clientOptions(clientOptions).build();

		RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration();

		configuration.setHostName("192.168.81.98");
		configuration.setPort(6379);
		configuration.setPassword("123456");

		LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory(configuration, lettuceClientConfiguration);

		lettuceConnectionFactory.afterPropertiesSet();

		RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(lettuceConnectionFactory);
		redisTemplate.setDefaultSerializer(RedisSerializer.string());
		redisTemplate.afterPropertiesSet();

		redisTemplate.opsForValue().set("b", "22");

		System.out.println(redisTemplate.opsForValue().get("b"));

	}
```



##### Redisson

```java
	public static void main(String[] args) throws Exception {
		// redisson配置文件
		Config config = new Config();
		config.setCodec(new JsonJacksonCodec());

		// 单机模式
		SingleServerConfig ssc = config.useSingleServer();

		// KeyManagerFactory
		KeyManagerFactory keyManagerFactory = keyManagerFactory("C:\\Java\\myredis\\certs\\redis-client.crt", "C:\\Java\\myredis\\certs\\redis-client.key");
		ssc.setSslKeyManagerFactory(keyManagerFactory);

		// TrustManagerFactory
		TrustManagerFactory trustManagerFactory = trustManagerFactory("C:\\Java\\myredis\\certs\\ca.crt");
		ssc.setSslTrustManagerFactory(trustManagerFactory);

		// 地址
		ssc.setAddress("rediss://192.168.81.98:6379");
		// 密码
		ssc.setPassword("123456");

		RedissonClient redissonClient = Redisson.create(config);

		// 获取 RBucket 对象
		RBucket<String> bucket = redissonClient.getBucket("aa");

		// 设置 Key-Value
		bucket.set("22");

		System.out.println(bucket.get());

	}

	private static KeyManagerFactory keyManagerFactory(String clientCertFile, String clientKeyFile) throws Exception {
		PrivateKey privateKey = null;

		// 1. 加载 redis.key 文件
		try (PEMParser pemParser = new PEMParser(new FileReader("C:\\Java\\myredis\\certs\\redis-client.key"))) {
			Object object = pemParser.readObject();

			// 2. 将 PEM 格式转换为 Java KeyPair
			JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
			KeyPair keyPair = keyConverter.getKeyPair((org.bouncycastle.openssl.PEMKeyPair) object);

			// 3. 提取私钥
			privateKey = keyPair.getPrivate();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 加载证书链
		Certificate[] certChain = new Certificate[1];
		try (FileInputStream fis = new FileInputStream("C:\\Java\\myredis\\certs\\redis-client.crt")) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			certChain[0] = certFactory.generateCertificate(fis);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 创建并初始化 KeyStore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);

		// 设置密钥条目
		String keyAlias = "redis-client";
		char[] keyPassword = null; // 如果私钥有密码，则提供密码
		keyStore.setKeyEntry(keyAlias, privateKey, keyPassword, certChain);

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, null);

		return keyManagerFactory;
	}

	private static TrustManagerFactory trustManagerFactory(String caCertFile) throws Exception {

		// 1. 创建一个新的 KeyStore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null); // 初始化空的 KeyStore

		// 2. 加载 CA 证书
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		Certificate caCertificate;
		try (FileInputStream caCertInputStream = new FileInputStream(caCertFile)) {
			caCertificate = certificateFactory.generateCertificate(caCertInputStream);
		}

		// 3. 将 CA 证书添加到 KeyStore
		String alias = "ca-cert"; // 为证书设置一个别名
		keyStore.setCertificateEntry(alias, caCertificate);

		// 4. 初始化 TrustManagerFactory
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		return trustManagerFactory;
	}

```



## 性能对比

### 未开启 ssl

```shell
C:\Users\10217>docker exec -it redis redis-benchmark -h 192.168.81.98 -p 6379 -a 123456 -c 100 -n 100000 -d 1024 -t set,get -q
SET: 20370.75 requests per second, p50=4.631 msec
GET: 20060.18 requests per second, p50=4.695 msec
```



### 开启 ssl

#### 忽略证书验证

```shell
C:\Users\10217>docker exec -it redis redis-benchmark --tls --insecure -h 192.168.81.98 -p 6379 -a 123456 -c 100 -n 100000 -d 1024 -t set,get -q
SET: 18439.98 requests per second, p50=4.775 msec
GET: 18511.66 requests per second, p50=4.695 msec
```

性能下降 9.5 %



#### 双向认证

```shell
C:\Users\10217>docker exec -it redis redis-benchmark --tls --cert /certs/redis-client.crt --key /certs/redis-client.key --cacert /certs/ca.crt -h 192.168.81.98 -p 6379 -a 123456 -c 100 -n 100000 -d 1024 -t set,get -q
SET: 17445.92 requests per second, p50=4.607 msec
GET: 17711.65 requests per second, p50=4.607 msec
```

性能下降 14.4 %



#### 结论

| 开启 ssl -  忽略证书验证 | 开启 ssl - 双向认证 |
| ------------------------ | ------------------- |
| 性能下降 9.5 %           | 性能下降 14.4 %     |



## 附录

### 自签证书

```shell
# 生成 CA 私钥和证书
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -days 3650 -out ca.crt -subj "/CN=Redis-CA"

# 生成 Redis 私钥和证书签名请求 (CSR)
openssl genrsa -out redis-server.key 4096
openssl req -new -key redis-server.key -out redis-server.csr -config openssl.cnf

# 使用 CA 签发 Redis 证书
openssl x509 -req -in redis-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out redis-server.crt -days 3650 -extensions v3_req -extfile openssl.cnf
```



openssl.cnf

```
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = 192.168.81.98  # 主机名（例如，Redis 节点主机名）

[ v3_req ]
keyUsage = keyEncipherment, digitalSignature, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = 192.168.81.98       # 主机名（可以有多个）
#DNS.2 = another-redis-host    # 其他主机名
IP.1 = 192.168.81.98           # 节点 IP 地址
#IP.2 = 192.168.1.11           # 其他节点 IP 地址
```

