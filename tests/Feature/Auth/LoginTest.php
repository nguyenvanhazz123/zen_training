<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\RateLimiter;
use Tests\TestCase;
use Tymon\JWTAuth\Facades\JWTAuth;

class LoginTest extends TestCase
{
    use RefreshDatabase;

    public function setUp(): void
    {
        parent::setUp();
        RateLimiter::clear('login-message:test@example.com');
    }

    /**
     * Test đăng nhập thành công.
     */
    public function test_user_logs_in_successfully()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->json('POST', '/login', [
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $response->assertStatus(200);
        $response->assertJsonStructure([
            'success',
            'user',
            'message',
            'access_token'
        ]);
    }

    /**
     * Test đăng nhập thất bại do sai mật khẩu.
     */
    public function test_login_fails_with_incorrect_password()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->json('POST', '/login', [
            'email' => 'test@example.com',
            'password' => 'wrongpassword'
        ]);

        $response->assertStatus(401);
        $response->assertJson([
            'success' => false,
            'message' => 'Incorrect password'
        ]);
    }

    /**
     * Test đăng nhập thất bại do validation errors.
     */
    public function test_login_fails_due_to_validation_errors()
    {
        $response = $this->json('POST', '/login', [
            'email' => 'test',
            'password' => ''
        ]);

        $response->assertStatus(422);
        $response->assertJsonStructure([
            'success',
            'message',
            'errors'
        ]);
    }

    /**
     * Test rate limiting.
     */
    public function test_login_rate_limiter()
    {
        for ($i = 0; $i < 5; $i++) {
            $response = $this->json('POST', '/login', [
                'email' => 'test@example.com',
                'password' => 'password123'
            ]);
        }

        $response = $this->json('POST', '/login', [
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);
        $response->assertStatus(429);
        $response->assertJson([
            'success' => false,
            'message' => 'Vui lòng đăng nhập sau'
        ]);
    }
}
