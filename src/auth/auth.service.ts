//src/auth/auth.service.ts
import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthEntity } from './entity/auth.entity';
import * as bcrypt from 'bcrypt';

const EXPIRE_TIME = 60 * 60 * 1000; // 1 hour in milliseconds

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async login(email: string, password: string): Promise<AuthEntity> {
    // Step 1: Fetch a user with the given email
    const user = await this.prisma.user.findUnique({ where: { email: email } });
    const payload = {
      username: user.email,
      sub: {
        name: user.name,
      },
    };
    // If no user is found, throw an error
    if (!user) {
      throw new NotFoundException(`No user found for email: ${email}`);
    }

    // Step 2: Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // If password does not match, throw an error
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Step 3: Generate a JWT token containing the user's ID and return it
    return {
      backendTokens: {
        accessToken: await this.jwtService.signAsync(payload, {
          expiresIn: '1h',
          secret: process.env.jwtSecretKey,
        }),
        refreshToken: await this.jwtService.signAsync(payload, {
          expiresIn: '7d',
          secret: process.env.jwtRefreshTokenKey,
        }),
        expiresIn: new Date().setTime(new Date().getTime() + EXPIRE_TIME),
      },
    };
  }

  async refreshTokens(refreshToken: string): Promise<AuthEntity> {
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.jwtRefreshTokenKey,
      });
  
      // Fetch user details again (if necessary)
      const user = await this.prisma.user.findUnique({
        where: { email: decoded.username }
      });
      if (!user) {
        throw new UnauthorizedException('User not found.');
      }
  
      const payload = {
        username: user.email,
        sub: {
          name: user.name,
        },
      };
  
      // Generate new access token
      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: '1h',
        secret: process.env.jwtSecretKey,
      });
  
      return {
        backendTokens: {
          accessToken,
          refreshToken, // Optionally, generate a new refresh token
          expiresIn: new Date().setTime(new Date().getTime() + EXPIRE_TIME),
        },
      };
    } catch (error) {
      // Token is invalid or expired
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }
  
}
