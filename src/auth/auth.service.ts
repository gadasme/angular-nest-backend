/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';

import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      // 1- Encriptar la contraseña
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
      // 2- Guardar el usuario
      // 3- Generar el JWT
    } catch (error) {
      console.log('error :>> ', error.code);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }
      throw new InternalServerErrorException('Internal Server Error');
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);
    return {
      user,
      token: this.getJwt({ id: user._id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    console.log({ loginDto });
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password');
    }
    const { password: _, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwt({ id: user.id }),
    };
  }

  async findUserbyId(id: string) {
    const user = await this.userModel.findById(id);
    const { password: _, ...rest } = user.toJSON();
    return rest;
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
