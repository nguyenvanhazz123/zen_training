<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Password;
use Tests\TestCase;

class SendResetLinkEmailTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test gửi email thay đổi mật khẩu thành công.
     */
    public function test_send_reset_link_email_successfully()
    {
        $user = User::factory()->create(['email' => 'test@example.com']);

        Password::shouldReceive('sendResetLink')
                ->once()
                ->with(['email' => 'test@example.com'])
                ->andReturn(Password::RESET_LINK_SENT);

        $response = $this->postJson('/api/password/email', ['email' => 'test@example.com']);

        $response->assertStatus(200);
        $response->assertJson(['success' => true, 'message' => "Đã gửi email thay đổi mật khẩu"]);
    }

    /**
     * Test gửi email thay đổi mật khẩu bị hạn chế (throttling).
     */
    public function test_send_reset_link_email_throttled()
    {
        Password::shouldReceive('sendResetLink')
                ->once()
                ->with(['email' => 'test@example.com'])
                ->andReturn(Password::RESET_THROTTLED);

        $response = $this->postJson('/api/password/email', ['email' => 'test@example.com']);

        $response->assertStatus(429);
        $response->assertJson(['success' => false, 'message' => "Too many attempts. Please try again later."]);
    }
}
