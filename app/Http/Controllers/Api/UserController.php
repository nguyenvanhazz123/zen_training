<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Validation\Rules;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function index() {
        $users = User::all();
        return response()->json([
            "status" => "success",
            "data" => $users,
        ], 201);
    }
    
    public function store(Request $request) {
        $request->validate([
            'fullname' => 'nullable|string|max:250',
            'username' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email', 
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
            'address' => 'nullable|string|max:250',
            'gender' => 'nullable|string|max:50',
            'DOB' => 'nullable|string|max:250',
        ]);

        $user = User::create([
            'fullname' => $request->fullname,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'address' => $request->address,
            'gender' => $request->gender,
            'DOB' => $request->DOB,
        ]);

        return response()->json($user, 201);
    }
    
    public function show($id) {
        try {
            $user = User::findOrFail($id);
            return response()->json([
                "status" => "success",
                "data" => $user,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                "status" => "error",
                "message" => "Invalid user ID",
            ], 400);
        }
    }
    
    public function update(Request $request, $id) {
        try {
            $user = User::findOrFail($id);
            $user->update($request->all());
            return response()->json($user);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid or corrupted user ID',
            ], 400);
        }
    }
    
    public function destroy($id) {
        try {
            $user = User::findOrFail($id);
            $user->delete();
            return response()->json(null, 204);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid or corrupted user ID',
            ], 400);
        }
    }
}
