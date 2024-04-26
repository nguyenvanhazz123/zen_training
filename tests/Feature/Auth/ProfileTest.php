<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ProfileTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test truy cập thông tin cá nhân khi đã đăng nhập.
     */
    public function test_user_can_view_profile()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'name' => 'Test User'
        ]);

        $this->actingAs($user);

        $response = $this->getJson('/profile');

        $response->assertStatus(200);
        $response->assertJson([
            'success' => true,
            'message' => 'Profile data',
            'data' => [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name
            ]
        ]);
    }

    /**
     * Test truy cập thông tin cá nhân khi chưa đăng nhập.
     */
    public function test_unauthenticated_user_cannot_view_profile()
    {
        $response = $this->getJson('/profile');

        $response->assertStatus(401);
    }
}
