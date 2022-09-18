import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { LoginDto } from './dto/LoginDto';
import { SignupDto } from './dto/SignupDto';
import { User } from './interfaces/user';

@Injectable()
export class AuthService {
  private users: User[] = [];

  constructor(private readonly jwtService: JwtService) {}

  findUser(username: string): User | undefined {
    return this.users.find((u) => u.username === username);
  }

  createAccessToken(username: string): { accessToken: string } {
    return { accessToken: this.jwtService.sign({ sub: username }) };
  }

  async signup(newUser: SignupDto): Promise<{ accessToken: string }> {
    if (this.users.find((u) => u.username === newUser.username)) {
      throw new ConflictException(
        `User with username ${newUser.username} already exists`,
      );
    }
    const user = {
      username: newUser.username,
      password: await argon2.hash(newUser.password),
      firstName: newUser.firstName,
      lastName: newUser.lastName,
    };
    this.users.push(user);
    return { accessToken: this.jwtService.sign({ sub: user.username }) };
  }

  async login(user: LoginDto): Promise<{ accessToken: string }> {
    try {
      const existingUser = this.findUser(user.username);
      if (!user) {
        throw new Error();
      }
      const passwordMatch = await argon2.verify(
        existingUser.password,
        user.password,
      );
      if (!passwordMatch) {
        throw new Error();
      }
      return this.createAccessToken(user.username);
    } catch (e) {
      throw new UnauthorizedException(
        'Username or password may be incorrect. Please try again',
      );
    }
  }
}
