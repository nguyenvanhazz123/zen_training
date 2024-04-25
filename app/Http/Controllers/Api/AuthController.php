<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\RateLimiter;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;


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
     *             @OA\Property(property="username", type="string", example="nguyenvanha"),
     *             @OA\Property(property="email", type="string", format="email", example="nguyenvanha@gmail.com"),
     *             @OA\Property(property="password", type="string", format="password", example="Aa@123456"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="Aa@123456")
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
     *             @OA\Property(property="email", type="string", format="email", example="nguyenvanha@gmail.com"),
     *             @OA\Property(property="password", type="string", format="password", example="Aa@123456")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful login",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="user", type="object"),
     *             @OA\Property(property="message", type="string", example="User logged in successfully"),
     *             @OA\Property(property="access_token", type="string", example="jwt_token_here")
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
             // Kiểm tra dữ liệu đầu vào
             $request->validate([
                "email" => "required|email|exists:users,email",
                "password" => "required"
            ]);

            //Dùng rate-limiter giới hạn mỗi email đăng nhập 5 lần / phút
            if (RateLimiter::tooManyAttempts('login-message:'.$request->email, $perMinute = 5)) {
                $seconds = RateLimiter::availableIn('login-message:'.$request->email);
             
                return response()->json([
                    "success" => false,
                    "message" => "Vui lòng đăng nhập sau $seconds giây",
                ], 429);
            }           
            RateLimiter::increment('login-message:'.$request->email);
    
            
            // JWTAuth: kiểm tra đăng nhập và tạo mã token từ email và password
            $token = JWTAuth::attempt([
                "email" => $request->email,
                "password" => $request->password,
            ]);
            //Lấy user đang đăng nhập
            $user = Auth::user();
    
            if (!empty($token)) {
                RateLimiter::clear('login-attempt:'.$request->email);
                return response()->json([
                    "success" => true,
                    'user' => $user,
                    "message" => "User logged in successfully",
                    "access_token" => $token,
                ], 200);
            } else {
                return response()->json([
                    "success" => false,
                    "message" => "Incorrect password",
                ], 401);
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
     *             @OA\Property(property="data", type="object", example={"username": "nguyenvanha", "email": "nguyenvanha@gmail.com"})
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

    /**
     * @OA\Post(
     *     path="/api/refresh-token",
     *     summary="Refresh JWT Token",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"token"},
     *             @OA\Property(property="token", type="string", example="Your_Refresh_Token_Here")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Token refreshed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="token", type="string", example="New_Access_Token")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid token provided"
     *     )
     * )
     */
    public function refresh_token()
    {
        try {
            $newToken = JWTAuth::parseToken()->refresh();
        } catch (JWTException $e) {
            return response()->json(['error' => 'token_invalid'], 401);
        }

        return response()->json(['token' => $newToken]);
    }

    /**
     * @OA\Post(
     *     path="/api/forgot-password",
     *     summary="Send Reset Password Link to Email",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Reset link sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Đã gửi email thay đổi mật khẩu")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Failed to send reset link",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Xảy ra lỗi")
     *         )
     *     )
     * )
     */
    public function sendResetLinkEmail(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        return $status == Password::RESET_LINK_SENT
               ? response()->json(['success' => true, 'message' => "Đã gửi email thay đổi mật khẩu"], 200)
               : response()->json(['success' => false, 'message' => "Xảy ra lỗi"], 422);
    }

    /**
     * @OA\Post(
     *     path="/api/reset-password",
     *     summary="Reset Password",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email", "token", "password", "password_confirmation"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="token", type="string", example="Your_Reset_Token"),
     *             @OA\Property(property="password", type="string", format="password", example="newpassword"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="newpassword")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Đổi mật khẩu thành công")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Password reset failed",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Mật khẩu xác thực sai")
     *         )
     *     )
     * )
     */
    public function reset(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|confirmed|min:8',
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->save();

                $user->setRememberToken(Str::random(60));

                event(new \Illuminate\Auth\Events\PasswordReset($user));
            }
        );

        return $status == Password::PASSWORD_RESET
               ? response()->json(['success' => true, 'message' => "Đổi mật khẩu thành công"])
               : response()->json(['success' => false, 'message' => "Mật khẩu xác thực sai"], 422);
    }

}
