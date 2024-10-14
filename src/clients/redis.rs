use bb8::Pool;
use bb8_redis::{redis::cmd, RedisConnectionManager};
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
    #[error("error occured while connecting to redis server")]
    RedisError,
}

impl RedisClient {
    pub async fn new(url: String) -> Result<Self, RedisError> {
        let manager: RedisConnectionManager = bb8_redis::RedisConnectionManager::new(url.clone())?;
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
        match bb8_redis::redis::Cmd::get(key)
            .query_async::<T>(&mut *conn)
            .await
        {
            Ok(v) => Ok(v),
            Err(_) => Err(RedisError::RedisError),
        }
    }

    pub async fn incr<T: bb8_redis::redis::FromRedisValue + bb8_redis::redis::ToRedisArgs>(
        &self,
        key: String,
        delta: T,
    ) -> Result<T, RedisError> {
        let mut conn = self.pool.get().await?;
        match bb8_redis::redis::Cmd::incr(key, delta)
            .query_async::<T>(&mut *conn)
            .await
        {
            Ok(v) => Ok(v),
            Err(_) => Err(RedisError::RedisError),
        }
    }
}
