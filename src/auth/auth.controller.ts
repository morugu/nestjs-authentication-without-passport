import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/LoginDto';
import { SignupDto } from './dto/SignupDto';
import { JwtGuard } from './guards/JwtGuard';
import { SignupPipe } from './pipes/SignupPipe';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body(SignupPipe) newUser: SignupDto) {
    console.log(newUser);
    return this.authService.signup(newUser);
  }

  @Post('login')
  async login(@Body() user: LoginDto) {
    return this.authService.login(user);
  }

  @Get('me')
  @UseGuards(JwtGuard)
  getProfile(@Request() req): any {
    return this.authService.findUser(req.user.sub);
  }
}
