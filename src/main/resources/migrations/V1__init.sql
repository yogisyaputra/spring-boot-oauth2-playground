create table if not exists users (
     id uuid primary key,
     email varchar(255) unique not null,
    name varchar(255),
    avatar_url text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_login_at timestamptz
    );

create table if not exists user_provider_accounts (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
    provider varchar(32) not null,
    provider_user_id varchar(128) not null,
    username varchar(255),
    profile_url text,
    constraint uq_provider_user unique (provider, provider_user_id)
    );
