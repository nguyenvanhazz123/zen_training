<?php

namespace Tests\Feature\Auth;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use App\Models\User;

class RegisterTest extends TestCase
{
    use RefreshDatabase; // Sử dụng để reset database sau mỗi test

    /**
     * Test đăng ký thành công.
     */
    public function test_registers_successfully()
    {
        $response = $this->json('POST', '/register', [
            'username' => 'newuser',
            'email' => 'newuser@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123'
        ]);

        $response->assertStatus(200);
        $response->assertJson([
            "status" => true,
            "message" => "User registered successfully"
        ]);
        $this->assertDatabaseHas('users', [
            'email' => 'newuser@example.com'
        ]);
    }

    /**
     * Test đăng ký thất bại do lỗi validation.
     */
    public function test_registration_fails_due_to_validation_errors()
    {
        User::create([
            'username' => 'existinguser',
            'email' => 'user@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->json('POST', '/register', [
            'username' => 'user',
            'email' => 'user@example.com',
            'password' => 'short',
            'password_confirmation' => 'short'
        ]);

        $response->assertStatus(422);
        $response->assertJsonStructure([
            'status',
            'message',
            'errors' => ['email', 'password']
        ]);
    }
}
