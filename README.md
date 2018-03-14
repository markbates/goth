# Goth + naver provider

## Introduction

Naver.com is the biggest search engine in South Korea. It even has a bigger share, compared to Google. Naver provides an oauth api but it seems there's no go library for it. Since I want to use it along with others(google, facebook oauth) I implemented it on goth.

## Documents regarding Naver api
english translation: https://www.drupal.org/files/issues/naver%20login_development%20guide.pdf

original: https://developers.naver.com/docs/login/api/


## Key and secret

Since creating key and secret needs korean citizenship(phone verification), I've made them. Also I added "http://localhost:3000/auth/naver/callback" as permitted callback url. You can use them freely.

Key: 4QqFkFjcJ0JCgWJLqPYE

Secret: t1sxmpJQNk


