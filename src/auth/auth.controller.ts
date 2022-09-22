import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { JwtGuard } from './guards/jwt.guard';
import { SignupPipe } from './pipes/signup.pipe';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body(SignupPipe) newUser: SignupDto) {
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
