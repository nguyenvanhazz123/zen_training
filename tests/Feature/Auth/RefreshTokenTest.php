<?php

namespace Tests\Feature\Auth;

use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RefreshTokenTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test làm mới token thành công.
     */
    public function test_refresh_token_successfully()
    {
        $user = User::factory()->create();
        $token = JWTAuth::fromUser($user);
        JWTAuth::setToken($token);

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])
                         ->getJson('/api/refresh_token'); // Đảm bảo route và method đúng

        $response->assertOk();
        $response->assertJsonStructure(['token']);
    }

    /**
     * Test làm mới token thất bại do token không hợp lệ.
     */
    public function test_refresh_token_fails_with_invalid_token()
    {
        $invalidToken = 'some.invalid.token';
        JWTAuth::setToken($invalidToken);

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $invalidToken])
                         ->getJson('/api/refresh_token');

        $response->assertStatus(401);
        $response->assertJson(['error' => 'token_invalid']);
    }
}
