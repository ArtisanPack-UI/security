---
title: AI Guidelines for Implementing Security
---

# AI Guidelines for Implementing Security

This guide provides AI-assisted best practices for implementing the ArtisanPack UI Security package in your Laravel applications and packages.

## Core Security Principles

When generating code that handles user data, always follow these principles:

1. **Sanitize all input** - Never trust data from users, forms, APIs, or external sources
2. **Escape all output** - Prevent XSS attacks by escaping data before rendering
3. **Use context-aware escaping** - Different contexts (HTML, attributes, JS, CSS, URLs) require different escaping
4. **Layer your security** - Combine sanitization, validation, and escaping for defense in depth

## Input Sanitization Implementation

### When to Sanitize

Sanitize data at the earliest point in your application flow - typically in controllers or form request classes.

### Form Request Implementation

```php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreCommentRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email' => 'required|email|max:255',
            'comment' => 'required|string|max:1000',
            'website' => 'nullable|url|max:255',
        ];
    }

    protected function prepareForValidation()
    {
        // Sanitize inputs before validation
        $this->merge([
            'email' => sanitizeEmail($this->email),
            'comment' => sanitizeText($this->comment),
            'website' => sanitizeUrl($this->website),
        ]);
    }
}
```

### Controller Implementation

```php
<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function store(Request $request)
    {
        // Sanitize input data
        $validated = $request->validate([
            'email' => 'required|email',
            'comment' => 'required|string',
            'rating' => 'required|integer|min:1|max:5',
        ]);

        // Sanitize after validation
        Comment::create([
            'email' => sanitizeEmail($validated['email']),
            'comment' => sanitizeText($validated['comment']),
            'rating' => sanitizeInt($validated['rating']),
            'user_id' => auth()->id(),
        ]);

        return redirect()->back()->with('success', 'Comment added!');
    }

    public function bulkUpdate(Request $request)
    {
        $validated = $request->validate([
            'comments' => 'required|array',
            'comments.*.id' => 'required|integer',
            'comments.*.text' => 'required|string',
        ]);

        // Sanitize array data
        $sanitized = sanitizeArray($validated['comments']);

        foreach ($sanitized as $comment) {
            Comment::find($comment['id'])->update([
                'text' => sanitizeText($comment['text']),
            ]);
        }

        return response()->json(['success' => true]);
    }
}
```

### Available Sanitization Functions

Choose the appropriate function based on the data type:

| Function | Use Case | Example |
|----------|----------|---------|
| `sanitizeEmail($email)` | Email addresses | User registration, contact forms |
| `sanitizeText($text)` | Plain text, removes HTML | Comments, descriptions, names |
| `sanitizeUrl($url)` | URLs and links | User-provided websites, links |
| `sanitizeInt($value)` | Integer values | IDs, counts, ratings |
| `sanitizeFloat($value)` | Decimal numbers | Prices, percentages, measurements |
| `sanitizeDate($date)` | Date strings | Birth dates, deadlines |
| `sanitizeDatetime($datetime)` | Datetime strings | Event timestamps, created_at |
| `sanitizeFilename($name)` | File names | Uploaded file names |
| `sanitizePassword($password)` | Password input | Login, registration forms |
| `sanitizeArray($array)` | Nested arrays | Bulk operations, JSON input |

## Output Escaping Implementation

### Blade View Implementation

Always escape user-generated content in your Blade templates:

```blade
{{-- Comment display --}}
<div class="comments">
    @foreach ($comments as $comment)
        <div class="comment">
            <div class="comment-author">
                {{-- Escape HTML content --}}
                {!! escHtml($comment->author_name) !!}
            </div>
            <div class="comment-text">
                {!! escHtml($comment->text) !!}
            </div>
            <a href="{{ escUrl($comment->website) }}"
               title="{{ escAttr($comment->website_title) }}"
               class="comment-link">
                Visit Website
            </a>
        </div>
    @endforeach
</div>

{{-- User profile with inline styles --}}
<div class="user-profile">
    <h2 style="color: {{ escCss($user->favorite_color) }}">
        {!! escHtml($user->name) !!}
    </h2>
    <div class="bio" data-bio="{{ escAttr($user->bio) }}">
        {!! escHtml($user->bio) !!}
    </div>
</div>

{{-- Dynamic JavaScript --}}
<script>
    var userData = {
        name: '{{ escJs($user->name) }}',
        email: '{{ escJs($user->email) }}',
        website: '{{ escJs($user->website) }}'
    };
    console.log('User: ' + userData.name);
</script>
```

### Component Implementation

```php
<?php

namespace App\View\Components;

use Illuminate\View\Component;

class UserCard extends Component
{
    public function __construct(
        public string $name,
        public string $bio,
        public string $website,
        public string $avatarUrl
    ) {}

    public function render()
    {
        return view('components.user-card');
    }

    // Helper methods for escaping in component
    public function safeHtml(string $content): string
    {
        return escHtml($content);
    }

    public function safeAttr(string $content): string
    {
        return escAttr($content);
    }
}
```

```blade
{{-- resources/views/components/user-card.blade.php --}}
<div class="user-card">
    <img src="{{ escUrl($avatarUrl) }}" alt="{{ escAttr($name) }}">
    <h3>{!! escHtml($name) !!}</h3>
    <p class="bio">{!! escHtml($bio) !!}</p>
    <a href="{{ escUrl($website) }}" target="_blank">Website</a>
</div>
```

### Context-Aware Escaping

| Context | Function | When to Use |
|---------|----------|-------------|
| HTML body | `escHtml()` | Inside HTML elements, displaying text content |
| HTML attributes | `escAttr()` | Inside attribute values (title, alt, data-*) |
| URLs | `escUrl()` | In href, src attributes |
| JavaScript | `escJs()` | Inside `<script>` tags or inline JS |
| CSS | `escCss()` | Inside `<style>` tags or inline styles |

## HTML Filtering Implementation

Use `kses()` when you need to allow some HTML tags but sanitize potentially dangerous content:

```php
<?php

namespace App\Http\Controllers;

use App\Models\BlogPost;
use Illuminate\Http\Request;

class BlogPostController extends Controller
{
    public function store(Request $request)
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
        ]);

        BlogPost::create([
            'title' => sanitizeText($validated['title']),
            // Allow safe HTML tags in blog content
            'content' => kses($validated['content']),
            'user_id' => auth()->id(),
        ]);

        return redirect()->route('posts.index');
    }
}
```

```blade
{{-- Display blog post with filtered HTML --}}
<article class="blog-post">
    <h1>{!! escHtml($post->title) !!}</h1>
    <div class="post-content">
        {{-- kses already filtered dangerous HTML --}}
        {!! $post->content !!}
    </div>
</article>
```

## Two-Factor Authentication Implementation

### Step 1: Database Setup

Create migration for 2FA columns:

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_enabled_at')->nullable();
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'two_factor_secret',
                'two_factor_recovery_codes',
                'two_factor_enabled_at',
            ]);
        });
    }
};
```

### Step 2: User Model Setup

```php
<?php

namespace App\Models;

use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use TwoFactorAuthenticatable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];
}
```

### Step 3: Controller Implementation

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use ArtisanPackUI\Security\Facades\TwoFactor;
use Illuminate\Http\Request;

class TwoFactorController extends Controller
{
    public function enable(Request $request)
    {
        $user = $request->user();

        // Enable 2FA for the user
        TwoFactor::enable($user);

        return redirect()
            ->route('profile.security')
            ->with('status', 'Two-factor authentication enabled');
    }

    public function disable(Request $request)
    {
        $user = $request->user();

        // Disable 2FA
        TwoFactor::disable($user);

        return redirect()
            ->route('profile.security')
            ->with('status', 'Two-factor authentication disabled');
    }

    public function challenge()
    {
        // Show 2FA code entry form
        return view('auth.two-factor-challenge');
    }

    public function verify(Request $request)
    {
        $request->validate([
            'code' => 'required|string',
        ]);

        $user = $request->user();
        $code = sanitizeText($request->input('code'));

        if (TwoFactor::verify($user, $code)) {
            // Mark session as 2FA verified
            $request->session()->put('two_factor_verified', true);

            return redirect()->intended(route('dashboard'));
        }

        return back()->withErrors([
            'code' => 'The provided code is invalid.',
        ]);
    }
}
```

### Step 4: Authentication Flow

```php
<?php

namespace App\Http\Controllers\Auth;

use ArtisanPackUI\Security\Facades\TwoFactor;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (auth()->attempt($credentials)) {
            $user = auth()->user();

            // Check if 2FA is enabled
            if ($user->hasTwoFactorEnabled()) {
                // Generate and send 2FA challenge
                TwoFactor::generateChallenge($user);

                return redirect()->route('two-factor.challenge');
            }

            return redirect()->intended('dashboard');
        }

        return back()->withErrors([
            'email' => 'Invalid credentials.',
        ]);
    }
}
```

### Step 5: Routes

```php
<?php

use App\Http\Controllers\Auth\TwoFactorController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth'])->group(function () {
    // Enable/disable 2FA
    Route::post('/user/two-factor/enable', [TwoFactorController::class, 'enable'])
        ->name('two-factor.enable');
    Route::delete('/user/two-factor/disable', [TwoFactorController::class, 'disable'])
        ->name('two-factor.disable');

    // 2FA challenge
    Route::get('/user/two-factor/challenge', [TwoFactorController::class, 'challenge'])
        ->name('two-factor.challenge');
    Route::post('/user/two-factor/verify', [TwoFactorController::class, 'verify'])
        ->name('two-factor.verify');
});
```

### Step 6: Challenge View

```blade
{{-- resources/views/auth/two-factor-challenge.blade.php --}}
<x-layout>
    <div class="two-factor-challenge">
        <h2>Two-Factor Authentication</h2>
        <p>Please enter the code sent to your email or from your authenticator app.</p>

        <form method="POST" action="{{ route('two-factor.verify') }}">
            @csrf

            <div class="form-group">
                <label for="code">Authentication Code</label>
                <input
                    id="code"
                    type="text"
                    name="code"
                    required
                    autofocus
                    maxlength="6"
                    placeholder="000000"
                >
                @error('code')
                    <span class="error">{{ $message }}</span>
                @enderror
            </div>

            <button type="submit">Verify</button>
        </form>
    </div>
</x-layout>
```

## Session Security Implementation

### Enable Encrypted Sessions

```php
<?php

// app/Http/Kernel.php
namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middleware = [
        // ... other middleware
        \ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted::class,
    ];
}
```

### Check Session Security

```bash
# Run artisan command to verify session encryption
php artisan security:check-session
```

## Best Practices Checklist

When generating code with AI assistance, ensure:

- [ ] All user input is sanitized using appropriate `sanitize*()` functions
- [ ] All output in views uses appropriate `esc*()` functions
- [ ] Context-aware escaping is used (HTML, attributes, JS, CSS, URLs)
- [ ] Forms include `@csrf` directive for CSRF protection
- [ ] Database queries use Eloquent or Query Builder (never raw SQL with user input)
- [ ] File uploads validate and sanitize filenames with `sanitizeFilename()`
- [ ] Rich text editors use `kses()` to filter allowed HTML
- [ ] 2FA is properly integrated into authentication flow
- [ ] Error messages don't expose sensitive information
- [ ] API responses escape data appropriately

## Common Patterns

### API Controller with Sanitization

```php
<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'description' => 'required|string',
            'price' => 'required|numeric|min:0',
            'category_id' => 'required|integer|exists:categories,id',
        ]);

        $product = Product::create([
            'name' => sanitizeText($validated['name']),
            'description' => kses($validated['description']),
            'price' => sanitizeFloat($validated['price']),
            'category_id' => sanitizeInt($validated['category_id']),
        ]);

        return response()->json([
            'id' => $product->id,
            'name' => escHtml($product->name),
            'description' => $product->description, // Already filtered with kses
            'price' => $product->price,
        ], 201);
    }
}
```

### Form with File Upload

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'bio' => 'nullable|string|max:1000',
            'avatar' => 'nullable|image|max:2048',
        ]);

        $user = $request->user();
        $user->name = sanitizeText($validated['name']);
        $user->bio = sanitizeText($validated['bio']);

        if ($request->hasFile('avatar')) {
            $file = $request->file('avatar');
            $filename = sanitizeFilename($file->getClientOriginalName());
            $path = $file->storeAs('avatars', $filename, 'public');
            $user->avatar_path = $path;
        }

        $user->save();

        return redirect()->route('profile.show');
    }
}
```

## Additional Resources

- [Complete API Reference](api-reference.md)
- [Security Guidelines](security-guidelines.md)
- [Two-Factor Authentication Guide](two-factor-authentication.md)
- [Getting Started](getting-started.md)
