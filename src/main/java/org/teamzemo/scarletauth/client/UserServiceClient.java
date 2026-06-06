package org.teamzemo.scarletauth.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.teamzemo.scarletauth.dto.UserSyncRequest;

@FeignClient(name = "scarlet-user", url = "${app.user-service-url:http://scarlet-user}")
public interface UserServiceClient {

    @PostMapping("/api/users/internal/sync")
    void syncUser(@RequestBody UserSyncRequest request);
}
