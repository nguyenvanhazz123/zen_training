<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Tests\TestCase;

class ResetPasswordTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test đổi mật khẩu thành công.
     */
    public function test_password_reset_success()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com'
        ]);

        Password::shouldReceive('reset')
                ->once()
                ->andReturn(Password::PASSWORD_RESET);

        $response = $this->postJson('/api/password/reset', [
            'token' => 'valid-token',
            'email' => 'test@example.com',
            'password' => 'newsecurepassword',
            'password_confirmation' => 'newsecurepassword'
        ]);

        $response->assertOk();
        $response->assertJson([
            'success' => true,
            'message' => "Đổi mật khẩu thành công"
        ]);
    }

    /**
     * Test đổi mật khẩu thất bại do token không hợp lệ.
     */
    public function test_password_reset_fails_with_invalid_token()
    {
        Password::shouldReceive('reset')
                ->once()
                ->andReturn(Password::INVALID_TOKEN);

        $response = $this->postJson('/api/password/reset', [
            'token' => 'invalid-token',
            'email' => 'test@example.com',
            'password' => 'newsecurepassword',
            'password_confirmation' => 'newsecurepassword'
        ]);

        $response->assertStatus(422);
        $response->assertJson([
            'success' => false,
            'message' => "Mật khẩu xác thực sai"
        ]);
    }
}
