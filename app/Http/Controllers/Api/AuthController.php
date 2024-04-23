<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
     // User Register (POST)
     public function register(Request $request){
        try {
            // Kiểm tra dữ liệu đầu vào
            $request->validate([
                "username" => "required",
                "email" => "required|email|unique:users",
                "password" => "required|confirmed",
            ]);

            // Tạo user mới nếu không lỗi
            User::create([
                "username" => $request->username,
                "email" => $request->email,
                "password" => Hash::make($request->password)
            ]);

            return response()->json([
                "status" => true,
                "message" => "User registered successfully"
            ], 200);
        } catch (ValidationException $e) {
            // Lấy ra tất cả các lỗi
            $errors = $e->errors();

            return response()->json([
                'status' => false,
                'message' => 'Error, not successfully',
                'errors' => $errors
            ], 422);
        }
       
    }

    // User Login (POST)
    public function login(Request $request){
        try {
            // Kiểm tra dữ liệu đầu vào
            $request->validate([
                "email" => "required|email|exists:users,email",
                "password" => "required"
            ]);

            // JWTAuth: kiểm tra đăng nhập
            $token = JWTAuth::attempt([
                "email" => $request->email,
                "password" => $request->password
            ]);

            if(!empty($token)){
                return response()->json([
                    "status" => true,
                    "message" => "User logged in successfully",
                    "token" => $token
                ], 200);
            }else {
                return response()->json([
                    "status" => false,
                    "message" => "Incorrect password",
                ], 422);
            }
        } catch (ValidationException $e) {
            $errors = $e->errors();

            return response()->json([
                'status' => false,
                'message' => 'Email does not exits',
                'errors' => $errors
            ], 422);
        }
    }

    // User Profile (GET)
    public function profile(){

        $userData = auth()->user();

        return response()->json([
            "status" => true,
            "message" => "Profile data",
            "data" => $userData
        ], 200);
    } 

    // User Logout (GET)
    public function logout(){
        
        auth()->logout();

        return response()->json([
            "status" => true,
            "message" => "User logged out successfully"
        ], 200);
    }

}
