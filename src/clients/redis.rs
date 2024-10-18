use bb8::Pool;
use bb8_redis::{
    redis::{cmd, AsyncCommands},
    RedisConnectionManager,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct RedisClient {
    pool: Pool<RedisConnectionManager>,
}

#[derive(Error, Debug)]
pub enum RedisError {
    #[error("redis server unreachable. failed to ping redis server")]
    RedisServerUnreachable,
    #[error("error occured while creating connection pool")]
    RedisConnectionError(#[from] bb8_redis::redis::RedisError),
    #[error("error occured while fetching connection from pool")]
    RedisConnectionPoolError(#[from] bb8::RunError<bb8_redis::redis::RedisError>),
}

impl RedisClient {
    pub async fn new(url: &String) -> Result<Self, RedisError> {
        let manager: RedisConnectionManager =
            bb8_redis::RedisConnectionManager::new(url.to_string())?;
        let pool = bb8::Pool::builder().max_size(20).build(manager).await?;
        // Attempt to ping redis
        let p = pool.clone();
        let mut conn = p.get().await?;
        match cmd("PING").query_async::<String>(&mut *conn).await {
            Ok(v) => {
                if v == "PONG" {
                    Ok(RedisClient { pool })
                } else {
                    Err(RedisError::RedisServerUnreachable)
                }
            }
            Err(_) => Err(RedisError::RedisServerUnreachable),
        }
    }

    pub async fn get<T: bb8_redis::redis::FromRedisValue>(
        &self,
        key: String,
    ) -> Result<T, RedisError> {
        let mut conn = self.pool.get().await?;
        let res = conn.get(key).await?;
        Ok(res)
    }

    pub async fn incr<
        T: bb8_redis::redis::FromRedisValue + bb8_redis::redis::ToRedisArgs + Send + Sync,
    >(
        &self,
        key: String,
        delta: T,
    ) -> Result<T, RedisError> {
        let mut conn = self.pool.get().await?;
        let res = conn.incr(key, delta).await?;
        Ok(res)
    }

    pub async fn setnx<T: bb8_redis::redis::ToRedisArgs + Send + Sync>(
        &self,
        key: String,
        value: T,
    ) -> Result<bool, RedisError> {
        let mut conn = self.pool.get().await?;
        let res: i32 = conn.set_nx(key, value).await?;
        Ok(res == 1)
    }

    pub async fn decr<
        T: bb8_redis::redis::FromRedisValue + bb8_redis::redis::ToRedisArgs + Send + Sync,
    >(
        &self,
        key: String,
        delta: T,
    ) -> Result<T, RedisError> {
        let mut conn = self.pool.get().await?;
        let res = conn.decr(key, delta).await?;
        Ok(res)
    }

    pub async fn expire(&self, key: String, delta: i64) -> Result<bool, RedisError> {
        let mut conn = self.pool.get().await?;
        let res = conn.expire(key, delta).await?;
        Ok(res)
    }
}
