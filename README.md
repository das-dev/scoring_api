```
curl --header "Content-Type: application/json" \
     --request POST \
     --data '{"account": "partner", "login": "me", "method": "online_score", "token": "token", "arguments": {}}' \
     http://localhost:8080/method
```