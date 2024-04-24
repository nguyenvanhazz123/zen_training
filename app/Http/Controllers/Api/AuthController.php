<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\RateLimiter;


 /**
 * @OA\SecurityScheme(
 *   securityScheme="bearerAuth",
 *   type="http",
 *   scheme="bearer",
 *   bearerFormat="JWT",
 *   in="header",
 *   description="Enter JWT Bearer token **_only_**"
 * )
 */
class AuthController extends Controller
{

     /**
     * @OA\Post(
     *     path="/api/register",
     *     tags={"Authentication"},
     *     summary="Registers a new user",
     *     description="Registers a new user with username, email, and password.",
     *     @OA\RequestBody(
     *         required=true,
     *         description="User registration data",
     *         @OA\JsonContent(
     *             required={"username", "email", "password", "password_confirmation"},
     *             @OA\Property(property="username", type="string", example="john_doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="your_password"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="your_password")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful registration",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User registered successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation Error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Error, not successfully"),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
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


    /**
     * @OA\Post(
     *     path="/api/login",
     *     tags={"Authentication"},
     *     summary="Logs in a user",
     *     description="Logs in a user by email and password and returns a JWT token.",
     *     @OA\RequestBody(
     *         required=true,
     *         description="User login data",
     *         @OA\JsonContent(
     *             required={"email", "password"},
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="your_password")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful login",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User logged in successfully"),
     *             @OA\Property(property="token", type="string", example="jwt_token_here")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation Error or Too Many Attempts",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Incorrect password or rate limit exceeded")
     *         )
     *     )
     * )
     */
    public function login(Request $request){
        try {
            
            //Dùng rate-limiter giới hạn mỗi email đăng nhập 5 lần / phút
            if (RateLimiter::tooManyAttempts('send-message:'.$request->email, $perMinute = 5)) {
                $seconds = RateLimiter::availableIn('send-message:'.$request->email);
             
                return response()->json([
                    "success" => false,
                    "message" => "Vui lòng đăng nhập sau $seconds giây",
                ], 422);
            }           
            RateLimiter::increment('send-message:'.$request->email);
            
    
            // Kiểm tra dữ liệu đầu vào
            $request->validate([
                "email" => "required|email|exists:users,email",
                "password" => "required"
            ]);
    
            // JWTAuth: kiểm tra đăng nhập và tạo mã token từ email và password
            $token = JWTAuth::attempt([
                "email" => $request->email,
                "password" => $request->password
            ]);
    
            if (!empty($token)) {
                return response()->json([
                    "success" => true,
                    "message" => "User logged in successfully",
                    "token" => $token
                ], 200);
            } else {

                return response()->json([
                    "success" => false,
                    "message" => "Incorrect password",
                ], 422);
            }
        } catch (ValidationException $e) {
            $errors = $e->errors();
    
            return response()->json([
                'success' => false,
                'message' => 'Validation error',
                'errors' => $errors
            ], 422);
        }
    }
    

    /**
     * @OA\Get(
     *     path="/api/profile",
     *     tags={"Authentication"},
     *     summary="User profile",
     *     description="Returns the profile of the authenticated user.",
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="Profile data retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Profile data"),
     *             @OA\Property(property="data", type="object", example={"username": "johndoe", "email": "johndoe@example.com"})
     *         )
     *     )
     * )
     */
    public function profile(){

        $userData = auth()->user();

        return response()->json([
            "success" => true,
            "message" => "Profile data",
            "data" => $userData
        ], 200);
    } 


    /**
     * @OA\Get(
     *     path="/api/logout",
     *     tags={"Authentication"},
     *     summary="Logs out the user",
     *     description="Logs out the user by invalidating the token.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User logged out successfully")
     *         )
     *     )
     * )
     */

    public function logout(){
        
        auth()->logout();

        return response()->json([
            "success" => true,
            "message" => "User logged out successfully"
        ], 200);
    }

}
