<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\RefreshToken;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Carbon;
use App\Jobs\SendResetPasswordEmail;    

 /**
 * @OA\Schema(
 *   schema="User",
 *   type="object",
 *   title="User",
 *   description="User account information",
 *   @OA\Property(property="id", type="integer", example=1),
 *   @OA\Property(property="username", type="string", example="john_doe"),
 *   @OA\Property(property="email", type="string", format="email", example="john.doe@example.com")
 * )
 * 
 *  * @OA\SecurityScheme(
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
     *     operationId="registerUser",
     *     tags={"Authentication"},
     *     summary="Register a new user",
     *     description="Register a new user by providing username, email, and password.",
     *     @OA\RequestBody(
     *         required=true,
     *         description="Pass user credentials",
     *         @OA\JsonContent(
     *             required={"username", "email", "password", "password_confirmation"},
     *             @OA\Property(property="username", type="string", example="john_doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="Password123"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="Password123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User successfully registered"),
     *             @OA\Property(property="user", type="object", ref="#/components/schemas/User"),
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="refresh_token", type="string", example="def50200d..."),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Invalid input data",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Invalid data provided"),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="email", type="array",
     *                     @OA\Items(type="string", example="The email field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Error in server",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Error, not successfully"),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="general", type="array",
     *                     @OA\Items(type="string", example="Internal Server Error")
     *                 )
     *             )
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
            $user = User::create([
                "username" => $request->username,
                "email" => $request->email,
                "password" => Hash::make($request->password)
            ]);

            // Tạo access token
            $token = Auth::guard('api')->login($user);

            // Tạo refresh token
            $refreshToken = Str::random(100);
            // $refreshToken = JWTAuth::refreshToken($token);
            RefreshToken::create([
                'user_id' => $user->id,
                'token' => $refreshToken,
                'expires_at' => Carbon::now()->addWeeks(1) // Thời hạn refresh token là một tuần
            ]);

            return response()->json([
                "status" => true,
                'message' => 'Đăng ký người dùng thành công',
                'user' => $user,
                'access_token' => $token,
                'refresh_token' => $refreshToken,
                'expires_in' => Auth::guard('api')->factory()->getTTL() * 60
            ], 200);
        } catch (ValidationException $e) {
            // Lấy ra tất cả các lỗi
            $errors = $e->errors();
            $message = "";

            if (isset($errors['email'])) {
                $message = "Email đã tồn tại";
            }
            else if (isset($errors['password'])) {
                $message = "Mật khẩu xác thực không chính xác";
            }

            return response()->json([
                'status' => false,
                'message' => $message,
                'errors' => $errors
            ], 500);
        }
       
    }


    /**
     * @OA\Post(
     *     path="/api/login",
     *     operationId="loginUser",
     *     tags={"Authentication"},
     *     summary="Logs in a user",
     *     description="Logs in by providing an email and password. Limits login attempts to 5 per minute per email.",
     *     @OA\RequestBody(
     *         required=true,
     *         description="User login credentials",
     *         @OA\JsonContent(
     *             required={"email", "password"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="pass1234")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful login",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="refresh_token", type="string", example="def50200d..."),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="error", type="string", example="Thông tin đăng nhập không chính xác")
     *         )
     *     ),
     *     @OA\Response(
     *         response=429,
     *         description="Too many login attempts",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Vui lòng đăng nhập sau {seconds} giây")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal Server Error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="An error occurred")
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]); 

        //Dùng rate-limiter giới hạn mỗi email đăng nhập 5 lần / phút
        if (RateLimiter::tooManyAttempts('login-message:'.$request->email, $perMinute = 5)) {
            $seconds = RateLimiter::availableIn('login-message:'.$request->email);

            return response()->json([
                "success" => false,
                "error" => "Vui lòng đăng nhập sau $seconds giây",
            ], 429);
        }           
        RateLimiter::increment('login-message:'.$request->email);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                "success" => false,
                'error' => 'Thông tin đăng nhập không chính xác'
            ], 401);
        }

        $user = Auth::user();
        $token = auth('api')->attempt($request->only('email', 'password'));

        $user->refreshTokens()->delete();
        $refreshToken = Str::random(100);
        // Lưu refresh token vào database
        $user->refreshTokens()->create([
            'token' => $refreshToken,
            'expires_at' => now()->addWeeks(1)
        ]);

        // $cookie = cookie('refresh_token', $refreshToken, 60 * 24 * 7, null, null, true, true); // 7 days

        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    

    /**
     * @OA\Get(
     *     path="/api/profile",
     *     tags={"Authentication"},
     *     summary="Get user profile",
     *     description="Retrieves the profile of the authenticated user. Requires a valid JWT token.",
     *     operationId="getUserProfile",
     *     security={{ "bearerAuth": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="Successful operation",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Dữ liệu thông tin người dùng"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 ref="#/components/schemas/User"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Token hết hạn không thể lấy thông tin người dùng")
     *         )
     *     )
     * )
     */
    public function profile(){
        try {
            $userData = auth()->user();

            return response()->json([
                "success" => true,
                "message" => "Dữ liệu thông tin người dùng",
                "data" => $userData
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                "success" => false,
                "message" => "Token hết hạn không thể lấy thông tin người dùng",
            ], 401);
        }
        
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
     *             @OA\Property(property="message", type="string", example="Đăng xuất thành công")
     *         )
     *     )
     * )
     */

    public function logout(){
        
        auth()->logout();

        return response()->json([
            "success" => true,
            "message" => "Đăng xuất thành công"
        ], 200);
    }

    /**
     * @OA\Post(
     *     path="/api/refresh-token",
     *     operationId="refreshAccessToken",
     *     tags={"Authentication"},
     *     summary="Refresh access token",
     *     description="Refreshes an expired access token using a refresh token stored in an HttpOnly cookie.",
     *     @OA\Response(
     *         response=200,
     *         description="Access token refreshed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized - No refresh token provided or token is invalid or expired",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Refresh token không tồn tại hoặc đã hết hạn")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="An error occurred")
     *         )
     *     )
     * )
     */
    public function refresh_token(Request $request)
    {
        $refreshToken = $request->bearerToken();

        if (!$refreshToken) {
            return response()->json(['error' => 'Refresh token không tồn tại'], 401);
        }

        $tokenData = RefreshToken::where('token', $refreshToken)
                                ->where('expires_at', '>', now())
                                ->first();

        if (!$tokenData) {
            return response()->json(['error' => 'Refresh token đã hết hạn. Vui lòng đăng nhập lại'], 401);
        }

        $user = User::find($tokenData->user_id);
        $newToken = auth('api')->tokenById($user->id);

        return response()->json([
            'access_token' => $newToken,
            'refresh_token' => $refreshToken,
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
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
     *             @OA\Property(property="message", type="string", example="Đã gửi email thay đổi mật khẩu, vui lòng kiểm tra email của bạn")
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
        try {
            $request->validate(['email' => 'required|email']);

            $status = Password::sendResetLink(
                $request->only('email')
            );
    
            return $status == Password::RESET_LINK_SENT
                   ? response()->json(['success' => true, 'message' => "Đã gửi email thay đổi mật khẩu, vui lòng kiểm tra email của bạn"], 200)
                   : response()->json(['success' => false, 'message' => "Email chưa được đăng ký"], 422);
        } catch (\Throwable $th) {
            return response()->json([
                "success" => false,
                "message" => "Vui lòng nhập đúng định dạng email"
            ]);
        }
        
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
